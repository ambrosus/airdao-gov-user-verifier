use proc_macro::TokenStream;
use quote::quote;
use sha3::{Digest, Keccak256};
use syn::parse_macro_input;

#[proc_macro]
pub fn event_signature(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as syn::LitStr);

    let data: Vec<u8> = From::from(input.value());
    let signature_bytes: [u8; 32] = Keccak256::digest(data).into();

    let token: proc_macro2::TokenStream = format!("ethereum_types::H256({:?})", signature_bytes)
        .parse()
        .unwrap();

    quote! { #token }.into()
}
