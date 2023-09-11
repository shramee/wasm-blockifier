import './style.css';
import logo from '/logo.svg';
import Dojo from 'dojo';

async function setup_app() {
  const { VITE_ACCOUNT, VITE_PRIVATE_KEY, VITE_WORLD, } = import.meta.env;

  const dojo = Dojo.fromCredentials({
    accountAddress: `${VITE_ACCOUNT}`,
    accountPrivateKey: `${VITE_PRIVATE_KEY}`,
    worldAddress: `${VITE_WORLD}`,
  });

  document.querySelector<HTMLDivElement>('#app')!.innerHTML = `
    <div>
      <a href="https://dojoengine.org" target="_blank">
        <img src="${logo}" class="logo" alt="Vite logo" />
      </a>
      <h1>Dojo starter</h1>
      <p class="read-the-docs">
        Your position component is: 
      </p>
      <p>
      <code id="position-component">0, 0</code>
      </p>
      <button id="spawn">Spawn</button>
    </div>
  `
  const $spawn = document.querySelector('#spawn');
  const $posLog = document.querySelector('#position-component');

  if ($spawn) {
    $spawn.addEventListener('click', () => {
      dojo.execute('spawn');
    })
  }
  if ($posLog) {
    setInterval(async () => {
      let pos = await dojo.entity("Position", VITE_ACCOUNT, 0, 2);
      $posLog.innerHTML = `${pos[1]}, ${pos[2]}`;
    }, 500);
  }
}

setup_app();