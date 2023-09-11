#[cfg(test)]
mod transactions {
    use std::path::PathBuf;

    use blockifier::abi::abi_utils::selector_from_name;
    use blockifier::execution::entry_point::CallEntryPoint;
    use blockifier::state::state_api::StateReader;
    use starknet_api::calldata;
    use starknet_api::transaction::Calldata;

    use super::super::client::Client;
    use super::super::utils::{addr, invoke_calldata, invoke_tx, ACCOUNT_ADDR, FEE_TKN_ADDR};

    #[test]
    fn state() {
        let mut client = Client::new();
        let s = client.state();
        let tkn_class = s.get_compiled_contract_class(&addr::class(FEE_TKN_ADDR));
        assert!(tkn_class.is_ok(), "tkn class missing");
        let acc_class = s.get_compiled_contract_class(&addr::class(ACCOUNT_ADDR));
        assert!(acc_class.is_ok(), "acc class missing");
        let tkn_contract = s.get_class_hash_at(addr::contract(FEE_TKN_ADDR));
        assert!(tkn_contract.unwrap() == addr::class(FEE_TKN_ADDR), "tkn contract incorrect class");
        let acc_contract = s.get_class_hash_at(addr::contract(ACCOUNT_ADDR));
        assert!(acc_contract.unwrap() == addr::class(ACCOUNT_ADDR), "acc contract incorrect class");
    }

    #[test]
    fn txn() {
        let mut client = Client::new();

        let txn = invoke_tx(
            ACCOUNT_ADDR,
            invoke_calldata(FEE_TKN_ADDR, "balanceOf", vec![ACCOUNT_ADDR]),
            None,
            "1",
        );

        let res = client.execute(txn);

        assert!(res.is_ok(), "Transaction failed");
        if let Ok(exec_info) = res {
            assert!(!exec_info.is_reverted(), "Transaction reverted");
            assert!(exec_info.execute_call_info.is_some(), "No execution call info");
        }
    }

    #[test]
    fn deploy_world() {
        let _ = PathBuf::from("../contracts/dojo-world-test.json");
        let mut client = Client::new();
        let account_json = include_bytes!("../../contracts/dojo-world-test.json");
        let account_json = String::from_utf8_lossy(account_json);

        client.register_sierra_class("0x3071d", &account_json).unwrap();
    }

    #[test]
    fn call() {
        let mut client = Client::new();

        let call = CallEntryPoint {
            calldata: calldata![addr::felt(ACCOUNT_ADDR)],
            storage_address: addr::contract(FEE_TKN_ADDR),
            entry_point_selector: selector_from_name("balanceOf"),
            initial_gas: 1000000000,
            ..Default::default()
        };
        let res = client.call(call);

        assert!(res.is_ok(), "Call failed");
        assert!(res.unwrap().execution.retdata.0.len() == 2, "Unexpected response");
    }
}
