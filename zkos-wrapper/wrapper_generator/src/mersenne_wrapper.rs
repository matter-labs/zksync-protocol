use zkos_verifier_generator::MersenneWrapper;

use proc_macro2::TokenStream;
use quote::quote;

pub(crate) struct MersenneBoojumWrapper;

impl MersenneWrapper for MersenneBoojumWrapper {
    fn field_struct() -> TokenStream {
        quote! { MersenneField<F> }
    }

    fn complex_struct() -> TokenStream {
        quote! { MersenneComplex<F> }
    }

    fn quartic_struct() -> TokenStream {
        quote! { MersenneQuartic<F> }
    }

    fn field_one() -> TokenStream {
        quote! { MersenneField::<F>::one(cs) }
    }

    fn field_new(value: TokenStream) -> TokenStream {
        quote! { MersenneField::<F>::allocate_constant(cs, Mersenne31Field(#value)) }
    }

    fn quartic_zero() -> TokenStream {
        quote! { MersenneQuartic::<F>::zero(cs) }
    }

    fn quartic_one() -> TokenStream {
        quote! { MersenneQuartic::<F>::one(cs) }
    }

    // The next functions use intermediate variable to cover the case, when `b` expression
    // contains function calls using cs.
    fn add_assign(a: TokenStream, b: TokenStream) -> TokenStream {
        quote! {{
            let intermediate = #b;
            #a = #a.add(cs, &intermediate)
        }}
    }

    fn sub_assign(a: TokenStream, b: TokenStream) -> TokenStream {
        quote! {{
            let intermediate = #b;
            #a = #a.sub(cs, &intermediate)
        }}
    }

    fn mul_assign(a: TokenStream, b: TokenStream) -> TokenStream {
        quote! {{
            let intermediate = #b;
            #a = #a.mul(cs, &intermediate)
        }}
    }

    fn add_assign_base(a: TokenStream, b: TokenStream) -> TokenStream {
        quote! {{
            let intermediate = #b;
            #a = #a.add_base(cs, &intermediate)
        }}
    }

    fn sub_assign_base(a: TokenStream, b: TokenStream) -> TokenStream {
        quote! {{
            let intermediate = #b;
            #a = #a.sub_base(cs, &intermediate)
        }}
    }

    fn mul_assign_by_base(a: TokenStream, b: TokenStream) -> TokenStream {
        quote! {{
            let intermediate = #b;
            #a = #a.mul_by_base(cs, &intermediate)
        }}
    }

    fn negate(a: TokenStream) -> TokenStream {
        quote! { #a = #a.negated(cs) }
    }

    fn generic_function_parameters() -> TokenStream {
        quote! {<F: SmallField, CS: ConstraintSystem<F>>}
    }

    fn additional_function_arguments() -> TokenStream {
        quote! {cs,}
    }

    fn additional_definition_function_arguments() -> TokenStream {
        quote! {cs: &mut CS,}
    }

    fn proof_aux_values_struct() -> TokenStream {
        quote! { WrappedProofAuxValues<F> }
    }

    fn aux_arguments_boundary_values_struct() -> TokenStream {
        quote! { WrappedAuxArgumentsBoundaryValues<F> }
    }
}
