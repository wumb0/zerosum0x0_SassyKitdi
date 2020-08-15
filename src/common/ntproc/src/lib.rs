
#[proc_macro]
#[cfg(not(debug_assertions))]
pub fn find(name: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let name = syn::parse_macro_input!(name as syn::LitStr);
    let mut name = name.value();

    name.push('\0');

    let x;

    unsafe {
        x = resolver::hash::fnv1a_32_hash(core::mem::transmute(name.as_bytes().as_ptr()), true, false);
    }

    //core::mem::transmute(resolver::get_proc_address(nt_base, ntstr::fnv1a_32_hash!("ExAllocatePool"))?),
    let result = quote::quote! {
        core::mem::transmute(resolver::get_proc_address(nt_base, #x as _ )?)
    };

    
        


    result.into()
}

#[proc_macro]
#[cfg(debug_assertions)]
pub fn find(name: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let name = syn::parse_macro_input!(name as syn::LitStr);
    let mut name = name.value();

    name.push('\0');

    let x:u32 = 0;

    //core::mem::transmute(resolver::get_proc_address(nt_base, ntstr::fnv1a_32_hash!("ExAllocatePool"))?),
    let result = quote::quote! {
        core::mem::transmute(resolver::get_proc_address(nt_base, #x as _ )?)
    };
        


    result.into()
}