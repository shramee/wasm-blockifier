import { debug, test_tx, register_class_sierra, register_contract } from "client-wasm";

interface ContractInfo {
	name: string,
	address?: string,
	abi: any,
	class_hash: string,
}

interface Manifest {
	world: ContractInfo,
	executor: ContractInfo,
	contracts: ContractInfo[],
	systems: ContractInfo[],
	components: ContractInfo[],
}

export default class LocalWorldHandler {
	manifestDir: URL;
	blockifier: any;
	manifest: Manifest | undefined;
	world_addr: string;
	constructor(manifestDir: URL, world_addr: string) {
		this.manifestDir = manifestDir;
		this.world_addr = world_addr;
		this.init();
	}

	async init() {
		// Blockifier WASM debugging
		debug();
		let manifest = await fetch(this.manifestDir + "/manifest.json").then(r => r.json());
		this.manifest = manifest;

		console.time('Loading and building classes');

		await this.initBase();
		// await this.initComponents();
		// await this.initSystems();

		console.timeEnd('Loading and building classes')
	}

	async initSystems() {
		if (!this.manifest) return;
		const { systems } = this.manifest;

		for (const contract of systems) {
			await this.processContract(contract)
		}

	}

	async initComponents() {
		if (!this.manifest) return;
		const { components } = this.manifest;

		for (const contract of components) {
			await this.processContract(contract)
		}

	}

	async initBase() {
		if (!this.manifest) return;
		const { world, executor } = this.manifest;
		this.processContract(world);
		this.processContract(executor);
	}

	async processContract(contract: ContractInfo, contract_addr: string = '') {
		const { name, class_hash } = contract;
		let class_bytecode_url = new URL(`${this.manifestDir}/dojo_examples-${name.toLowerCase()}.json`);
		let bytecode = await fetch(class_bytecode_url).then(r => r.text());
		console.log("\n\n\n", name, class_hash, bytecode.length);
		register_class_sierra(class_hash, bytecode);

		if (!contract_addr) contract_addr = class_hash;
		// register_contract(class_hash, class_hash);
	}
}