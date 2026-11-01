extern crate proc_macro;

use proc_macro::{Literal, TokenStream, TokenTree};

#[proc_macro]
pub fn manifest_dir(_: TokenStream) -> TokenStream {
    TokenTree::Literal(Literal::string(env!("CARGO_MANIFEST_DIR"))).into()
}
