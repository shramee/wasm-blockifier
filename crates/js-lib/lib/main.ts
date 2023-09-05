import { Account, BigNumberish, RpcProvider } from "starknet";
import { RPCProvider, strTofelt252Felt } from "@dojoengine/core";

type DojoCredentialArgs = {
	accountAddress: string,
	accountPrivateKey: string,
	worldAddress: string,
	nodeUrl?: string
};

export default class Dojo {
	account: Account;
	provider: RPCProvider;
	world: string;

	/**
	 * Creates Dojo instance from account address and secret key
	 * @param args {DojoCredentialArgs}
	 * @returns {Dojo}
	 * @example Dojo.fromCredentials({
		accountAddress: '0xf00',
		accountPrivateKey: '0xfaa',
		worldAddress: '0xfab',
	 })
	 */
	static fromCredentials(args: DojoCredentialArgs): Dojo {
		const
			sn_provider = new RpcProvider({ nodeUrl: args.nodeUrl || 'http://localhost:5050' }),
			account = new Account(sn_provider, args.accountAddress, args.accountPrivateKey);

		return new Dojo(account, args.worldAddress, args.nodeUrl || 'http://localhost:5050');
	}

	/**
	 * Constructs Dojo class
	 * Easier to instantiate with Dojo.fromCredentials
	 * @param {Account} account
	 * @param {string} worldAddress 
	 * @param {string} nodeUrl
	 */
	constructor(account: Account, worldAddress: string, nodeUrl: string) {
		this.world = worldAddress;

		this.account = account;
		this.provider = new RPCProvider(worldAddress, nodeUrl);
	}

	/**
	 * Executes a system with account
	 * @param {string} system 
	 * @param {BigNumberish[]} calldata Strings/Number/BigNumber array/single value
	 * @returns {Promise<InvokeFunctionResponse>}
	 * @example dojo.execute('spawn');
	 */
	execute(system: string, calldata: BigNumberish[] = []) {
		return this.provider.execute(this.account, system, calldata);

		// calldata = [strTofelt252Felt(system), calldata.length, ...calldata]
		// return this.account.execute({
		// 	contractAddress: this.world,
		// 	calldata: calldata,
		// 	entrypoint: 'execute',
		// });
	}

	/**
	 * Calls a system with account
	 * THIS METHOD IS NOT TESTED
	 * @param {string} system 
	 * @param {BigNumberish[]} calldata Strings/Number/BigNumber array/single value
	 * @returns {Promise<CallContractResponse>} Response from call
	 */
	call(system: string, calldata: BigNumberish[] = []) {
		calldata = [strTofelt252Felt(system), calldata.length, ...calldata]
		return this.account.callContract({
			contractAddress: this.world,
			calldata: calldata,
			entrypoint: 'execute',
		});
	}

	/**
	 * Fetches an entity
	 * @param {string} component 
	 * @param {BigNumberish[]} keys 
	 * @param {number} offset 
	 * @param {number} length 
	 * @returns {Promise<string[]>} Number of requested length, first element is the `length`
	 * number itself followed by `length` elements
	 * @example dojo.entity("Position", '0xb0b', 0, 2)
	 */
	async entity(component: string, keys: BigNumberish[], offset: number = 0, length: number = 1) {
		const keysArr: BigNumberish[] = typeof keys !== 'object' ? [keys] : keys;
		const calldata = [strTofelt252Felt(component), keysArr.length, ...keysArr, offset.toString(), length.toString()];
		let { result } = await this.account.callContract({
			contractAddress: this.world,
			calldata,
			entrypoint: 'entity',
		});

		return result;
	}
}
