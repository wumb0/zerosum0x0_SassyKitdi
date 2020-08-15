#[proc_macro]
pub fn init_unicode_str(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = syn::parse_macro_input!(item as syn::Ident);
    let name = &input;

    // Our input function is always equivalent to returning 42, right?
    let result = quote::quote! {
        ntdef::structs::UNICODE_STRING {
            Length: (core::mem::size_of_val(&#name) - 2) as u16,
            MaximumLength: (core::mem::size_of_val(&#name)) as u16,
            //Reserved0x4: [0u8, 0, 0, 0],
            Buffer: #name.as_mut_ptr() as _
        }   
    };
    result.into()
}


#[proc_macro]
pub fn fnv1a_32_hash(
    name: proc_macro::TokenStream
) -> proc_macro::TokenStream {
    let name = syn::parse_macro_input!(name as syn::LitStr);
    let mut name = name.value();

    name.push('\0');

    let x;

    unsafe {
        x = resolver::hash::fnv1a_32_hash(core::mem::transmute(name.as_bytes().as_ptr()), true, false);
    }

    let result = quote::quote! {
        #x 
    };


    result.into()
}