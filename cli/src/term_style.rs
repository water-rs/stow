//! Lightweight ANSI styling for user-facing CLI output.
//!
//! Color is enabled only when stdout is a terminal and `NO_COLOR` is unset
//! (or empty), or when `CLICOLOR_FORCE` is set to a non-empty value other
//! than `"0"`. `NO_COLOR` always disables color; `TERM=dumb` disables color
//! unless forced.

use std::ffi::OsString;
use std::fmt;
use std::io::IsTerminal as _;

/// ANSI styling state for a single output render.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    enabled: bool,
}

impl Palette {
    /// Resolve color support for `stdout` from the process environment.
    #[must_use]
    pub fn for_stdout() -> Self {
        Self::from_env(std::io::stdout().is_terminal(), |key| std::env::var_os(key))
    }

    /// Resolve color support from explicit TTY state and environment lookup.
    #[must_use]
    pub fn from_env(is_tty: bool, lookup: impl Fn(&str) -> Option<OsString>) -> Self {
        if lookup("NO_COLOR").is_some_and(|value| !value.is_empty()) {
            return Self { enabled: false };
        }
        if lookup("CLICOLOR_FORCE").is_some_and(|value| !value.is_empty() && value != "0") {
            return Self { enabled: true };
        }
        if !is_tty {
            return Self { enabled: false };
        }
        if lookup("TERM").is_some_and(|value| value == "dumb") {
            return Self { enabled: false };
        }
        Self { enabled: true }
    }

    /// Plain unstyled output (no ANSI escape sequences).
    #[cfg(test)]
    #[must_use]
    pub const fn plain() -> Self {
        Self { enabled: false }
    }

    /// Styled ANSI output.
    #[cfg(test)]
    #[must_use]
    pub const fn colored() -> Self {
        Self { enabled: true }
    }

    /// Whether ANSI escapes are emitted by this palette.
    #[cfg(test)]
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        self.enabled
    }

    #[must_use]
    pub const fn bold<T>(self, value: T) -> Styled<T> {
        self.wrap("\x1b[1m", value)
    }

    #[must_use]
    pub const fn dim<T>(self, value: T) -> Styled<T> {
        self.wrap("\x1b[2m", value)
    }

    #[must_use]
    pub const fn heading<T>(self, value: T) -> Styled<T> {
        self.wrap("\x1b[1;36m", value)
    }

    #[must_use]
    pub const fn key<T>(self, value: T) -> Styled<T> {
        self.wrap("\x1b[36m", value)
    }

    #[must_use]
    pub const fn ok<T>(self, value: T) -> Styled<T> {
        self.wrap("\x1b[32m", value)
    }

    #[must_use]
    pub const fn ok_bold<T>(self, value: T) -> Styled<T> {
        self.wrap("\x1b[1;32m", value)
    }

    #[must_use]
    pub const fn warn<T>(self, value: T) -> Styled<T> {
        self.wrap("\x1b[33m", value)
    }

    #[must_use]
    pub const fn err<T>(self, value: T) -> Styled<T> {
        self.wrap("\x1b[31m", value)
    }

    const fn wrap<T>(self, code: &'static str, value: T) -> Styled<T> {
        Styled {
            enabled: self.enabled,
            code,
            value,
        }
    }
}

/// Zero-allocation `Display` wrapper applying an SGR code when enabled.
#[derive(Debug, Clone, Copy)]
pub struct Styled<T> {
    enabled: bool,
    code: &'static str,
    value: T,
}

impl<T: fmt::Display> fmt::Display for Styled<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.enabled {
            write!(f, "{}{}\x1b[0m", self.code, self.value)
        } else {
            fmt::Display::fmt(&self.value, f)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::Palette;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        move |key| {
            pairs
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| OsString::from(value))
        }
    }

    #[test]
    fn palette_honors_tty_no_color_clicolor_force_and_dumb_term() {
        assert!(Palette::from_env(true, env(&[])).is_enabled());
        assert!(!Palette::from_env(false, env(&[])).is_enabled());
        // Empty NO_COLOR has no effect per no-color.org; any non-empty value disables color.
        assert!(Palette::from_env(true, env(&[("NO_COLOR", "")])).is_enabled());
        assert!(!Palette::from_env(true, env(&[("NO_COLOR", "1")])).is_enabled());
        assert!(
            !Palette::from_env(true, env(&[("NO_COLOR", "1"), ("CLICOLOR_FORCE", "1")]))
                .is_enabled()
        );
        // CLICOLOR_FORCE enables color on non-TTY unless set to "0" or empty.
        assert!(Palette::from_env(false, env(&[("CLICOLOR_FORCE", "1")])).is_enabled());
        assert!(!Palette::from_env(false, env(&[("CLICOLOR_FORCE", "0")])).is_enabled());
        assert!(!Palette::from_env(false, env(&[("CLICOLOR_FORCE", "")])).is_enabled());
        // TERM=dumb disables color on TTY unless forced.
        assert!(!Palette::from_env(true, env(&[("TERM", "dumb")])).is_enabled());
        assert!(
            Palette::from_env(true, env(&[("TERM", "dumb"), ("CLICOLOR_FORCE", "1")])).is_enabled()
        );
    }

    #[test]
    fn plain_palette_emits_no_ansi_escapes_and_colored_wraps_with_reset() {
        let plain = Palette::plain();
        assert_eq!(plain.heading("Cargo wiring").to_string(), "Cargo wiring");
        assert_eq!(plain.ok("on").to_string(), "on");

        let colored = Palette::colored();
        assert_eq!(
            colored.heading("Cargo wiring").to_string(),
            "\x1b[1;36mCargo wiring\x1b[0m"
        );
        assert_eq!(colored.ok("on").to_string(), "\x1b[32mon\x1b[0m");
    }
}
