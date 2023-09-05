Dojo: Unopinionated
===================

Basic Dojo wrapper.

You can use it like so,
```ts
const dojo = Dojo.fromCredentials({
	accountAddress: '0xf00',
	accountPrivateKey: '0xfaa',
	worldAddress: '0xfab',
});

// Get entity
dojo.entity("Position", '0xb0b', 0, 2)

// Execute a system
dojo.execute('move', '0x1');
```

## Docs

### Constructors

- [constructor](default.html#constructor)

### Properties

- [account](default.html#account)
- [provider](default.html#provider)
- [world](default.html#world)

### Methods

- [call](default.html#call)
- [entity](default.html#entity)
- [execute](default.html#execute)
- [fromCredentials](default.html#fromCredentials)

Constructors
------------

### constructor[](#constructor)

*   new default(account, worldAddress, nodeUrl): [default](default.html)[](#constructor.new_default)
*   Constructs Dojo class
*  	Easier to instantiate with Dojo.fromCredentials    
    #### Parameters
    
    *   ##### account: Account
        
    *   ##### worldAddress: string
        
    *   ##### nodeUrl: string
        
    
    #### Returns [default](default.html)
    
    *   Defined in [main.ts:40](https://github.com/shramee/dojo-js/blob/343ddc7/lib/main.ts#L40)
    

Properties
----------

### account[](#account)

account: Account

*   Defined in [main.ts:12](https://github.com/shramee/dojo-js/blob/343ddc7/lib/main.ts#L12)

### provider[](#provider)

provider: RPCProvider

*   Defined in [main.ts:13](https://github.com/shramee/dojo-js/blob/343ddc7/lib/main.ts#L13)

### world[](#world)

world: string

*   Defined in [main.ts:14](https://github.com/shramee/dojo-js/blob/343ddc7/lib/main.ts#L14)

Methods
-------

### call[](#call)

*   call(system, calldata?): Promise<CallContractResponse\>[](#call.call-1)
*   Calls a system with account THIS METHOD IS NOT TESTED
    
    #### Parameters
    
    *   ##### system: string
        
    *   ##### calldata: BigNumberish\[\] = \[\]
        
        Strings/Number/BigNumber array/single value
        
    
    #### Returns Promise<CallContractResponse\>
    
    Response from call
    
    *   Defined in [main.ts:72](https://github.com/shramee/dojo-js/blob/343ddc7/lib/main.ts#L72)
    

### entity[](#entity)

*   entity(component, keys, offset?, length?): Promise<string\[\]\>[](#entity.entity-1)
*   Fetches an entity
    
    #### Parameters
    
    *   ##### component: string
        
    *   ##### keys: BigNumberish\[\]
        
    *   ##### offset: number = 0
        
    *   ##### length: number = 1
        
    
    #### Returns Promise<string\[\]\>
    
    Number of requested length, first element is the `length` number itself followed by `length` elements
    
    #### Example
    
        dojo.entity("Position", '0xb0b', 0, 2)
        
    
    *   Defined in [main.ts:91](https://github.com/shramee/dojo-js/blob/343ddc7/lib/main.ts#L91)
    

### execute[](#execute)

*   execute(system, calldata?): Promise<InvokeFunctionResponse\>[](#execute.execute-1)
*   Executes a system with account
    
    #### Parameters
    
    *   ##### system: string
        
    *   ##### calldata: BigNumberish\[\] = \[\]
        
        Strings/Number/BigNumber array/single value
        
    
    #### Returns Promise<InvokeFunctionResponse\>
    
    #### Example
    
        dojo.execute('spawn');
        
    
    *   Defined in [main.ts:54](https://github.com/shramee/dojo-js/blob/343ddc7/lib/main.ts#L54)
    

### `Static` fromCredentials[](#fromCredentials)

*   fromCredentials(args): [default](default.html)[](#fromCredentials.fromCredentials-1)
*   Creates Dojo instance from account address and secret key
    
    #### Parameters
    
    *   ##### args: DojoCredentialArgs
        
        {DojoCredentialArgs}
        
    
    #### Returns [default](default.html)
    
    #### Example
    
        Dojo.fromCredentials({accountAddress: '0xf00',accountPrivateKey: '0xfaa',worldAddress: '0xfab',})
        
    
    *   Defined in [main.ts:26](https://github.com/shramee/dojo-js/blob/343ddc7/lib/main.ts#L26)