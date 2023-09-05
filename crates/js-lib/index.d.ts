import { Account, BigNumberish } from "starknet";
import { RPCProvider } from "@dojoengine/core";
type DojoCredentialArgs = {
	accountAddress: string;
	accountPrivateKey: string;
	worldAddress: string;
	nodeUrl?: string;
};

export default class Dojo {
	account: Account;
	provider: RPCProvider;
	world: string;
	static fromCredentials(args: DojoCredentialArgs): Dojo;
	constructor(account: Account, worldAddress: string, nodeUrl: string);
	execute(system: string, calldata?: BigNumberish[]): any;
	call(system: string, calldata?: BigNumberish[]): any;
	entity(component: string, keys: string[], offset?: number, length?: number): Promise<any>;
}
export { };
