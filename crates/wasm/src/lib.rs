mod utils;
use std::sync::Mutex;

use blockifier_utils::utils::{
    addr, invoke_calldata, invoke_tx, selector_from_name, CallEntryPoint, Calldata, HashMap,
    StarkFelt, DEPLOYER_ADDR,
};
use blockifier_utils::Client;
use utils::set_panic_hook;
use wasm_bindgen::prelude::*;

#[macro_use]
extern crate lazy_static;

lazy_static! {
    pub static ref CLIENT: Mutex<Client> = Mutex::new(Client::new());
}

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);

    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[wasm_bindgen]
pub fn debug() {
    set_panic_hook();
    log("Panic hook set");
}

#[wasm_bindgen]
pub fn test_tx() -> JsValue {
    let res = execute(
        "0x100".into(),
        "0x1".into(),
        "balanceOf".into(),
        serde_wasm_bindgen::to_value(&vec!["0x1", "0x100"]).unwrap(),
    );

    res
}

#[wasm_bindgen]
pub fn register_class_sierra(hash: String, json: String) -> bool {
    let mut client = CLIENT.lock().unwrap();
    match client.register_class(&hash, &json) {
        Ok(_) => true,
        Err(e) => {
            log(&format!("{:?}", e));
            false
        }
    }
}

#[wasm_bindgen]
pub fn register_class_raw(hash: String, json: String) -> bool {
    let mut client = CLIENT.lock().unwrap();
    match client.register_class(&hash, &json) {
        Ok(_) => true,
        Err(e) => {
            log(&format!("{:?}", e));
            false
        }
    }
}

#[wasm_bindgen]
pub fn register_class_v0(hash: String, json: String) -> bool {
    let mut client = CLIENT.lock().unwrap();
    match client.register_class_v0(&hash, &json) {
        Ok(_) => true,
        Err(e) => {
            log(&format!("{:?}", e));
            false
        }
    }
}

// #[wasm_bindgen]
// pub fn deploy_contract(
//     address: String,
//     class_hash: String,
//     salt: String,
//     calldata: JsValue,
//     caller: String,
// ) -> JsValue { let calldata: Vec<String> = serde_wasm_bindgen::from_value(calldata).unwrap(); let
//   calldata = calldata.iter().map(|cd| cd.as_str()).collect(); // classHash, salt ,unique,
//   calldata_len, calldata execute( caller, DEPLOYER_ADDR.into(), "deployContract".into(),
//   serde_wasm_bindgen::to_value(vec![class_hash, address, salt]).unwrap(), )
// }

#[wasm_bindgen]
pub fn register_contract(address: String, class_hash: String) -> bool {
    let mut client = CLIENT.lock().unwrap();
    match client.register_contract(&address, &class_hash, HashMap::new()) {
        Ok(_) => true,
        Err(e) => {
            log(&format!("{:?}", e));
            false
        }
    }
}

#[wasm_bindgen]
pub fn build_storage_key(storage_var_name: String, args: JsValue) -> JsValue {
    let args: Vec<String> = match serde_wasm_bindgen::from_value(args) {
        Ok(val) => val,
        Err(e) => {
            log(&format!("Err: {}", e));
            return JsValue::FALSE;
        }
    };
    let args: Vec<&str> = args.iter().map(|e| e.as_str()).collect();
    log(&format!("{}, Args: {:?}", storage_var_name, args));
    JsValue::from_str(&format!("{:?}", addr::storage(&storage_var_name, &args)))
}

// #[wasm_bindgen]
// pub fn get_state() -> HashMap<(ContractAddress), StarkFelt> {
//     let mut client = CLIENT.lock().unwrap();
//     client.cache();
// }

#[wasm_bindgen]
pub fn execute(caller: String, callee: String, entrypoint: String, calldata: JsValue) -> JsValue {
    let calldata: Vec<String> = serde_wasm_bindgen::from_value(calldata).unwrap();
    let calldata = calldata.iter().map(|cd| cd.as_str()).collect();

    log(&format!(
        "caller: {} callee: {} entrypoint: {} \n\n{:?}",
        &caller, &callee, &entrypoint, calldata
    ));

    let tx = invoke_tx(&caller, invoke_calldata(&callee, &entrypoint, calldata), None, "1");
    let mut client = CLIENT.lock().unwrap();

    if !client.state().contracts.contains_key(&addr::contract(&caller)) {
        client.register_contract(&caller, "0x100", HashMap::new()).unwrap();
    }

    let tx_res = client.execute(tx);

    match tx_res {
        Ok(exec_info) => {
            let exec_call_info = exec_info.execute_call_info.unwrap();

            serde_wasm_bindgen::to_value(&exec_call_info.accessed_storage_keys).unwrap()
        }
        Err(tx_err) => {
            log(&format!("{:#?}", tx_err));
            JsValue::FALSE
        }
    }
}

#[wasm_bindgen]
pub fn call(contract: String, entry_point: String, calldata: JsValue) -> JsValue {
    log(&format!("contract: {contract} entrypoint: {entry_point} \n\n{:?}", calldata));

    let calldata: Vec<String> = serde_wasm_bindgen::from_value(calldata).unwrap();
    let calldata: Vec<StarkFelt> = calldata.iter().map(|cd| addr::felt(cd.as_str())).collect();
    let entry_point_selector = selector_from_name(entry_point.as_str());

    // let tx = invoke_tx(&caller, invoke_calldata(&contract, &entrypoint, calldata), None, "1");
    let mut client = CLIENT.lock().unwrap();

    let call = CallEntryPoint {
        calldata: Calldata(calldata.into()),
        storage_address: addr::contract(&contract),
        entry_point_selector,
        initial_gas: 1000000000,
        ..Default::default()
    };

    let call_res = client.call(call);

    match call_res {
        Ok(result) => {
            if result.execution.failed {
                JsValue::FALSE
            } else {
                serde_wasm_bindgen::to_value(&result.execution.retdata.0).unwrap()
            }
        }
        Err(err) => {
            log(&format!("{:#?}", err));
            JsValue::FALSE
        }
    }
}
