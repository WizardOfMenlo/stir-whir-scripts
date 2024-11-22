use stir_whir_estimation::{
    field::GOLDILOCKS_2,
    stir::{StirConfig, StirParameters},
    LowDegreeParameters,
};

fn main() {
    let ldt_parameters = LowDegreeParameters {
        field: GOLDILOCKS_2,
        log_degree: 20,
        batch_size: 1,
    };

    let stir_parameters = StirParameters {
        starting_log_inv_rate: 1,
        starting_folding_factor: 4,
        folding_factors: vec![4, 4, 4, 4],
        evaluation_domain_log_sizes: vec![20, 19, 18, 17],

        security_assumption: stir_whir_estimation::errors::SecurityAssumption::CapacityBound,
        security_level: 100,
        pow_bits: 20,
    };

    let stir_config = StirConfig::new(ldt_parameters, stir_parameters);

    println!("{}", stir_config);
}
