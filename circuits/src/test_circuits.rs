use super::*;

use paste::paste;

macro_rules! circuit_inner {
    ($id:ident, $main_gate:ty, $declare_rescue:expr, $( $synth:tt ),*) => {
        #[derive(Clone, Debug)]
        pub struct $id;

        impl<E: Engine> Circuit<E> for $id {
            type MainGate = $main_gate;

            fn synthesize<CS: ConstraintSystem<E>>(
                &self,
                cs: &mut CS,
            ) -> Result<(), SynthesisError> {
                inner_circuit_main_gate_part(cs)?;
                $(
                    $synth(cs)?;
                )*

                Ok(())
            }

            fn declare_used_gates() -> Result<Vec<Box<dyn GateInternal<E>>>, SynthesisError> {
                let has_rescue = $declare_rescue;
                if has_rescue{
                    Ok(vec![
                        Self::MainGate::default().into_internal(),
                        Rescue5CustomGate::default().into_internal(),
                    ])
                }else{
                    Ok(vec![
                        Self::MainGate::default().into_internal(),                        
                    ])
                }                
            }
        }
    };
}

#[macro_export]
macro_rules! circuit {
    ($id:ident, $main_gate:ty) => {
        circuit_inner!($id, $main_gate, false, inner_circuit_main_gate_part);
        paste!{
            circuit_inner!([<$id WithLookup>], $main_gate, false,  inner_circuit_lookup_part);
        }
        paste!{
            circuit_inner!([<$id WithRescue>], $main_gate, true, inner_circuit_rescue_part);
        }
        paste!{
            circuit_inner!([<$id WithLookupAndRescue>], $main_gate, true, inner_circuit_lookup_part, inner_circuit_rescue_part);
        }
    }
}

circuit!(DummyCircuit, Width4MainGateWithDNext);
circuit!(
    SelectorOptimizedDummyCircuit,
    SelectorOptimizedWidth4MainGateWithDNext
);

fn inner_circuit_main_gate_part<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
) -> Result<(), SynthesisError> {
    for _ in 0..32 {
        let a = Num::alloc(cs, Some(E::Fr::one()))?;
        let b = Num::alloc(cs, Some(E::Fr::zero()))?;
        let flag = Boolean::alloc(cs, Some(true))?;
        let c = Num::conditionally_select(cs, &flag, &a, &b)?;
        let is_equal = Num::equals(cs, &a, &c)?;

        Boolean::enforce_equal(cs, &is_equal, &Boolean::Constant(true))?;
    }

    Ok(())
}

fn inner_circuit_lookup_part<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
) -> Result<(), SynthesisError> {
    // add dummy lookup table queries
    let dummy = CS::get_dummy_variable();
    dbg!("HAS LOOKUP");
    // need to create a table (any)
    let columns = vec![
        PolyIdentifier::VariablesPolynomial(0),
        PolyIdentifier::VariablesPolynomial(1),
        PolyIdentifier::VariablesPolynomial(2),
    ];
    let range_table = LookupTableApplication::new_range_table_of_width_3(2, columns.clone())?;
    let _range_table_name = range_table.functional_name();

    let xor_table = LookupTableApplication::new_xor_table(2, columns.clone())?;
    let _xor_table_name = xor_table.functional_name();

    let and_table = LookupTableApplication::new_and_table(2, columns)?;
    let and_table_name = and_table.functional_name();

    cs.add_table(range_table)?;
    cs.add_table(xor_table)?;
    cs.add_table(and_table)?;

    let binary_x_value = E::Fr::from_str("3").unwrap();
    let binary_y_value = E::Fr::from_str("1").unwrap();

    let t = AllocatedNum::zero(cs);
    let tt = AllocatedNum::one(cs);
    let ttt = t.mul(cs, &tt)?;
    ttt.inputize(cs)?;

    let binary_x = cs.alloc(|| Ok(binary_x_value))?;

    let binary_y = cs.alloc(|| Ok(binary_y_value))?;

    let table = cs.get_table(&and_table_name)?;
    let num_keys_and_values = table.width();

    let and_result_value = table.query(&[binary_x_value, binary_y_value])?[0];

    let binary_z = cs.alloc(|| Ok(and_result_value))?;

    cs.begin_gates_batch_for_step()?;

    let vars = [binary_x, binary_y, binary_z, dummy];
    cs.allocate_variables_without_gate(&vars, &[])?;

    cs.apply_single_lookup_gate(&vars[..num_keys_and_values], table)?;

    cs.end_gates_batch_for_step()?;

    Ok(())
}

fn inner_circuit_rescue_part<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
) -> Result<(), SynthesisError> {
    dbg!("HAS RESCUE");
    // make single rescue hash to satisfy gate requirements of declaration
    let mut params = RescueParams::default();
    params.use_custom_gate(CustomGate::QuinticWidth4);

    let elem = Num::alloc(cs, Some(E::Fr::from_str("42").unwrap()))?;
    let _ = circuit_generic_hash::<_, _, _, 2, 3, 2>(cs, &[elem, elem], &params, None)?;

    Ok(())
}

pub fn generate_setup_vk_and_proof_for_std_main_gate<E: Engine, C: Circuit<E>, T: Transcript<E::Fr>>(
    circuit: &C,
    transcript_params: Option<T::InitializationParameters>,
    prefix: &str,
) -> Result<(), SynthesisError> {
    let worker = Worker::new();

    let mut cs = TrivialAssembly::<
        E,
        PlonkCsWidth4WithNextStepAndCustomGatesParams,
        Width4MainGateWithDNext,
    >::new();

    circuit.synthesize(&mut cs)?;
    cs.finalize();

    assert!(cs.is_satisfied());

    let setup = cs.create_setup::<C>(&worker)?;

    println!("domain size {}", setup.n);

    let domain_size = setup.n.clone();

    let crs = Crs::<E, CrsForMonomialForm>::crs_42(domain_size.next_power_of_two(), &worker);

    let vk = VerificationKey::from_setup(&setup, &worker, &crs)?;
    dbg!(vk.total_lookup_entries_length);

    let vk_file_name = format!("/tmp/{}_{}", prefix, "vk_keccak.key");
    let proof_file_name = format!("/tmp/{}_{}", prefix, "proof_keccak.proof");

    let mut vk_writer = std::fs::File::create(vk_file_name).expect("create vk file");
    vk.write(&mut vk_writer).expect("write vk into file");
    let proof = cs.create_proof::<_, T>(&worker, &setup, &crs, transcript_params.clone())?;

    let mut proof_writer = std::fs::File::create(proof_file_name).expect("create proof file");
    proof
        .write(&mut proof_writer)
        .expect("write proof into file");
    let verified = verifier::verify::<E, _, T>(&vk, &proof, transcript_params)?;

    assert!(verified, "proof verification failed");

    Ok(())
}

#[cfg(test)]
mod circuit_tests {
    use std::path::PathBuf;
    use crate::generate::generate;

    use franklin_crypto::bellman::{
        bn256::{Bn256, Fr},
        kate_commitment::{Crs, CrsForMonomialForm},
        plonk::{
            better_better_cs::{
                cs::{
                    Assembly, Circuit, ConstraintSystem, Gate, GateInternal, LookupTableApplication,
                    PlonkCsWidth4WithNextStepAndCustomGatesParams, PolyIdentifier, Setup,
                    TrivialAssembly,
                },
                gates::{
                    main_gate_with_d_next::Width4MainGateWithDNext,
                    selector_optimized_with_d_next::SelectorOptimizedWidth4MainGateWithDNext,
                },
                proof::Proof,
                setup::VerificationKey,
                verifier,
            },
            commitments::transcript::{keccak_transcript::RollingKeccakTranscript, Transcript},
        },
        worker::Worker,
        Engine, Field, PrimeField, ScalarEngine, SynthesisError,
    };

    use super::*;

    fn generate_setup_vk_and_proof_for_selector_optimized_main_gate<
        E: Engine,
        C: Circuit<E>,
        T: Transcript<E::Fr>,
    >(
        circuit: &C,
        transcript_params: Option<T::InitializationParameters>,
        prefix: &str,
    ) -> Result<(), SynthesisError> {
        let worker = Worker::new();
        let mut cs = TrivialAssembly::<
            E,
            PlonkCsWidth4WithNextStepAndCustomGatesParams,
            SelectorOptimizedWidth4MainGateWithDNext,
        >::new();

        circuit.synthesize(&mut cs)?;
        cs.finalize();

        assert!(cs.is_satisfied());

        let setup = cs.create_setup::<C>(&worker)?;

        println!("domain size {}", setup.n);

        let domain_size = setup.n.clone();

        let crs = Crs::<E, CrsForMonomialForm>::crs_42(domain_size.next_power_of_two(), &worker);

        let vk = VerificationKey::from_setup(&setup, &worker, &crs)?;
        dbg!(vk.total_lookup_entries_length);
        // println!("{:#?}", vk);

        let vk_file_name = format!("/tmp/{}_{}", prefix, "vk_keccak.key");
        let proof_file_name = format!("/tmp/{}_{}", prefix, "proof_keccak.proof");

        let mut vk_writer = std::fs::File::create(vk_file_name).expect("create vk file");
        vk.write(&mut vk_writer).expect("write vk into file");
        let proof = cs.create_proof::<_, T>(&worker, &setup, &crs, transcript_params.clone())?;

        let mut proof_writer = std::fs::File::create(proof_file_name).expect("create proof file");
        proof
            .write(&mut proof_writer)
            .expect("write proof into file");
        let verified = verifier::verify::<E, _, T>(&vk, &proof, transcript_params)?;

        assert!(verified, "proof verification failed");

        Ok(())
    }

    #[test]
    fn test_create_vk_and_proof_file_for_std_main_gate() {
        {
            let circuit = DummyCircuit;
            generate_setup_vk_and_proof_for_std_main_gate::<
                Bn256,
                _,
                RollingKeccakTranscript<<Bn256 as ScalarEngine>::Fr>,
            >(&circuit, None, "width4")
            .unwrap()
        }
        {
            let circuit = DummyCircuitWithLookup;
            generate_setup_vk_and_proof_for_std_main_gate::<
                Bn256,
                _,
                RollingKeccakTranscript<<Bn256 as ScalarEngine>::Fr>,
            >(&circuit, None, "width4_with_lookup")
            .unwrap()
        }
        {
            let circuit = DummyCircuitWithRescue;
            generate_setup_vk_and_proof_for_std_main_gate::<
                Bn256,
                _,
                RollingKeccakTranscript<<Bn256 as ScalarEngine>::Fr>,
            >(&circuit, None, "width4_with_rescue")
            .unwrap()
        }
        {
            let circuit = DummyCircuitWithLookupAndRescue;
            generate_setup_vk_and_proof_for_std_main_gate::<
                Bn256,
                _,
                RollingKeccakTranscript<<Bn256 as ScalarEngine>::Fr>,
            >(&circuit, None, "width4_with_lookup_and_rescue")
            .unwrap()
        }
    }

    #[test]
    fn test_create_vk_and_proof_file_for_selector_optimized_main_gate() {
        {
            let circuit = SelectorOptimizedDummyCircuit;
            generate_setup_vk_and_proof_for_selector_optimized_main_gate::<
                Bn256,
                _,
                RollingKeccakTranscript<<Bn256 as ScalarEngine>::Fr>,
            >(&circuit, None, "selector_optimized")
            .unwrap()
        }
        {
            let circuit = SelectorOptimizedDummyCircuitWithLookup;
            generate_setup_vk_and_proof_for_selector_optimized_main_gate::<
                Bn256,
                _,
                RollingKeccakTranscript<<Bn256 as ScalarEngine>::Fr>,
            >(&circuit, None, "selector_optimized_with_lookup")
            .unwrap()
        }
        {
            let circuit = SelectorOptimizedDummyCircuitWithRescue;
            generate_setup_vk_and_proof_for_selector_optimized_main_gate::<
                Bn256,
                _,
                RollingKeccakTranscript<<Bn256 as ScalarEngine>::Fr>,
            >(&circuit, None, "selector_optimized_with_rescue")
            .unwrap()
        }
        {
            let circuit = SelectorOptimizedDummyCircuitWithLookupAndRescue;
            generate_setup_vk_and_proof_for_selector_optimized_main_gate::<
                Bn256,
                _,
                RollingKeccakTranscript<<Bn256 as ScalarEngine>::Fr>,
            >(
                &circuit,
                None,
                "selector_optimized_with_lookup_and_rescue",
            )
            .unwrap()
        }
    }

    #[test]
    fn test_render_vk_with_default_main_gate() {
        generate(
            PathBuf::from("./../block_vk_20_keccak.key"),
            PathBuf::from("./../hardhat/contracts"),
            None,
        );
    }

    #[test]
    fn test_generate_vk_and_proof_for_dummy_circuit_with_selector_optimized_main_gate() {
        generate(
            PathBuf::from("./../block_vk_20_keccak.key"),
            PathBuf::from("./../hardhat/contracts"),
            None,
        );
    }

    #[test]
    fn test_verification_keys() {
        {
            let reader = std::fs::File::open("/tmp/width4_vk_keccak.key").expect("open file");
            let vk = VerificationKey::<Bn256, DummyCircuit>::read(&reader).unwrap();
            assert_eq!(vk.gate_selectors_commitments.len(), 0);
            assert_eq!(
                <DummyCircuit as Circuit<Bn256>>::declare_used_gates()
                    .unwrap()
                    .len(),
                1
            );
        }
        {
            let reader =
                std::fs::File::open("/tmp/width4_with_lookup_vk_keccak.key").expect("open file");
            let vk = VerificationKey::<Bn256, DummyCircuitWithLookup>::read(&reader).unwrap();
            assert_eq!(vk.gate_selectors_commitments.len(), 0);
            assert_eq!(
                <DummyCircuitWithLookup as Circuit<Bn256>>::declare_used_gates()
                    .unwrap()
                    .len(),
                1
            );
        }
        {
            let reader =
                std::fs::File::open("/tmp/width4_with_rescue_vk_keccak.key").expect("open file");
            let vk = VerificationKey::<Bn256, DummyCircuitWithRescue>::read(&reader).unwrap();
            assert_eq!(vk.gate_selectors_commitments.len(), 2);
            assert_eq!(
                <DummyCircuitWithRescue as Circuit<Bn256>>::declare_used_gates()
                    .unwrap()
                    .len(),
                2
            );
        }
        {
            let reader = std::fs::File::open("/tmp/width4_with_lookup_and_rescue_vk_keccak.key")
                .expect("open file");
            let vk = VerificationKey::<Bn256, DummyCircuitWithLookupAndRescue>::read(&reader).unwrap();
            assert_eq!(vk.gate_selectors_commitments.len(), 2);
            assert_eq!(
                <DummyCircuitWithLookupAndRescue as Circuit<Bn256>>::declare_used_gates()
                    .unwrap()
                    .len(),
                2
            );
        }
    }

}