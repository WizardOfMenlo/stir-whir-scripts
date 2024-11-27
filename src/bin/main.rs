use stir_whir_estimation::{
    errors::SecurityAssumption,
    //field::GOLDILOCKS_2,
    field::BABYBEAR_5,
    fri::{FriConfig, FriParameters},
    stir::{StirConfig, StirParameters},
    LowDegreeParameters,
};

fn main() {
    let ldt_parameters = LowDegreeParameters {
        field: BABYBEAR_5,
        log_degree: 30,
        batch_size: 10,
    };

    let stir_parameters =
        StirParameters::fixed_domain_shift(1, 4, 4, SecurityAssumption::CapacityBound, 100, 20);
    let stir_config = StirConfig::new(ldt_parameters, stir_parameters);

    let fri_parameters =
        FriParameters::fixed_folding(1, 4, 4, SecurityAssumption::CapacityBound, 100, 20);
    let fri_config = FriConfig::new(ldt_parameters, fri_parameters);

    println!("{}", stir_config);
    println!("{}", fri_config);
}
