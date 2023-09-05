import './style.css'
import Dojo from '../lib/main'

declare global { var dojo: Dojo; }

const $f: HTMLFormElement | null = document.querySelector('form#app');

if ($f) {
	function setup($f: HTMLFormElement) {
		let d = new FormData($f);
		window.dojo = Dojo.fromCredentials({
			accountAddress: d.get('account')?.toString() || '',
			accountPrivateKey: d.get('skey')?.toString() || '',
			worldAddress: d.get('world')?.toString() || '',
			nodeUrl: d.get('rpc')?.toString() || '',
		});

	}
	$f.addEventListener('submit', e => {
		e.preventDefault();
		setup($f);
	});
	setTimeout(() => setup($f), 250);
}

export default Dojo;