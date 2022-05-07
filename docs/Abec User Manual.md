# ABEl User Manual

The following instructions will lead you to set up a full node (mining and keeping a copy of the full chain) and create an ABEL wallet.

We start from ABEL wallet first since we need to create address by wallet and then use the address to mine.

## 1. Download Abewallet and Abec

After getting **Abewallet** and **Abec** in compressed format, unzip them and store them in some folder, for example, abel/abewallet and abel/abec, respectively.

## 2. Create a wallet
**Notice**: For security concern, abewallet should be created and run on a secure machine.

To create a wallet,

```shell
# Macos and Linux
./start_abewallet.sh --create
# Windows
abewallet --create
```

**Hint 1:** On Macos and Linux, you may need to run `chmod 777 xxx` if it says ` xxx: Permission denied`. 
Then run abewallet again. 
Same when launching abec later.

**Hint 2**: On Macos, if it says `'xxx' cannot be opened because the developer cannot be verified`, 
go to `System Preferences -> Security & Privacy -> General` and click `allow anyway`. 
Then run abewallet again. 
Same when launching abec later.

Here is an example.

```shell
./start_abewallet.sh --create
Enter the private passphrase for your new wallet:
Confirm passphrase:
Enter the public passphrase for your new wallet:
Confirm passphrase:
NOTE: Use the --walletpass option to configure your public passphrase.
Do you have an existing wallet seed you want to use? (n/no/y/yes) [no]:
Your wallet generation seed is:
afe0f025646cde3eee099db9215f8cdb212ed0e06730fd0087e9d1ff5565fd53
the crypto version is 0
Your wallet mnemonic list is:
quiz,always,announce,silver,social,buyer,return,crisp,rice,april,tobacco,rent,base,half,light,toward,wonder,aerobic,whip,physical,vocal,real,vocal,leg
IMPORTANT: Keep the version and seed in a safe place as you
will NOT be able to restore your wallet without it.
Please keep in mind that anyone who has access
to the seed can also restore your wallet thereby
giving them access to all your funds, so it is
imperative that you keep it in a secure location.
Once you have stored the seed in a safe and secure location, enter "OK" to continue: OK
Creating the wallet...
Please remember the initial address:
00000000005a38589d86427698e3ec735335b368899ed6e0239c4285bbc4e370f4ea4e6d2ac1f1555b53f8df7c30e13d4bccc3b6d56763ec279620d9f131fb68089cb8ef18885950f84e56bf78d1780a5cac57d0888dabd669f86f85e7055afabae6a332fa000b3c6ee6a09751ce41ad7de4e...
```

The **public passphrase** would be used when launching abewallet, 
and the **private passphrase** would be used to unlock the wallet (to spend money). 
Both public passphrase and private passphrase are required and should be different.
Please keep both passphrases safe. 

Keep the **crypto version** and  **mnemonic list** in a safe place, 
it can be used to recover the wallet in the future in case you lose your wallet or want to move your wallet to another computer.

The **initial address** can be used as mining address or payment address later.

## 3. Launch Abec

To start running a full node, we need to run abec first to generate a configuration file.

```shell
# Macos and Linux
./start_abec.sh
# Windows
abec
```

Then press control+C to shut down abec.

You can find configuration file named *abec.conf* in **home directory** of the system. That is in

- Windows: C:\\Users\\[username]\\AppData\\Local\\Abec
- Macos: /Users/[username]/Library/Application Support/Abec
- Linux: /home/[username]/.abec

These folders are the **configuration folders** of abec. 
Some configurations are needed:.


### Peers

In abec.conf, we use addpeer to add some specific Abelian full nodes so that you can connect to the Abelian mainnet via these nodes.
At this moment, this is required.

```
addpeer = [IP:PORT]
```

At this moment, you can add one or more of the following peers, or any other peers you know.

```
addpeer = 18.117.106.180:8666
addpeer = 3.145.81.196:8666
addpeer = 3.66.221.224:8666
addpeer = 3.120.150.60:8666
```

Note that, if you do not specify the port, default port (8666) will be used.

### Listen Ports
In abec.conf, the default listen ports is 8666.
If you would like to use any other ports (in the scope (1025~65535)), for example 18666, you can specify it by

```
listen=:18666
```

### Broadcast your address
In addition to the above fixed full nodes that you can connect to via addpeer, 
you can also let other nodes know you through broadcasting your address. 
Otherwise, your node cannot be discovered by other nodes that you do not have their addresses in your abec.conf via addpeer.

If your machine has a public net IP (e.g., 1.2.3.4), you can let other nodes by specifying the external IP in abec.conf:

```
externalip=1.2.3.4
```

If you are using some other ports (e.g. 18666) rather than the default port (8666), 
you need to specify the port as well:

```
externalip=1.2.3.4:18666
```

If your node sits behind a router, and (1) the router has a public net IP and (2) the router has upnp enabled, in abec.conf, you can set:

```
upnp=1
```

***Note***: you need to check the log in the configuration folder to make sure that upnp is successfully established.

If your node sits behind a router, and 
(1) the router has a public net IP 
but (2) it does not support upnp, 
you need to (1) specify the external IP in abec.conf, like externalip=1.2.3.4 as shown above, 
and (2) set the port mapping/forwarding for the listening port on the router.


### RPC Server

To let your ABEL wallet, namely, abewallet, connect with the abec full node, we need to know the values of rpcuser and rpcpass, which are in abec.conf.

```
rpcuser = [administrator username]
rpcpass = [administrator password]
```

You may keep these automatically generated rpcuser and rpcpass values unchanged, and also create two more lines, namely

```
rpclimituser = [username]
rpclimitpass = [password]
```

as long as the values of rpcuser and rpclimituser are different.


### Mining

If you want to run the full node abec also as a mining node (which I think you do), you need to include the initial address of your ABEL wallet to the miningaddr option in the abec.conf configuration file:

```
miningaddr = [your initial address]
```


After finishing the configuration, we can start the abec again:

```shell
# Macos and Linux
./start_abec.sh --generate
# Windows
abec --generate
```

The above command makes abec start mining. If you do not want to let abec go mining, just run

```shell
# Macos and Linux
./start_abec.sh
# Windows
abec
```

```shell
# Macos and Linux
./start_abec.sh
# Windows
abec
```

Example:

```shell
./start_abec.sh --generate
2022-04-16 20:28:50.804 [INF] ABEC: Version 0.9.6
2022-04-16 20:28:50.837 [INF] ABEC: Loading block database from 'C:\Users\username\AppData\Local\Abec\data\mainnet\blocks_ffldb'
2022-04-16 20:28:50.848 [INF] ABEC: Block database loaded
2022-04-16 20:28:50.862 [INF] CHAN: Loading block index...
2022-04-16 20:28:50.862 [INF] CHAN: Chain state (height 17, hash 00000050ec9493c9f615dae1300b2f64e18220eca7bb4e17885cb87b3a9b5d2c, totaltx 19, work 150996096)
2022-04-16 20:28:50.865 [INF] RPCS: RPC server listening on 0.0.0.0:8667
2022-04-16 20:28:50.865 [INF] AMGR: Loaded 0 addresses from file 'C:\Users\username\AppData\Local\Abec\data\mainnet\peers.json'
2022-04-16 20:28:50.865 [INF] CMGR: Server listening on 0.0.0.0:8666
2022-04-16 20:28:50.865 [INF] CMGR: Server listening on [::]:8666
```

### Other options

Other options and their usage can be found in abec.conf.


## 4. Connect Abewallet to Abec

**Notice**: For security concern, abewallet should be running on a secure machine instead of running on the same machine as abec. 
If you run abec (a full node) on multiple machines, there is no need to create abewallet for each full node. 
**One wallet is enough.** You only need to add the mining address of the same wallet to the abec.conf of each of your mining machines and connect abewallet to just **one** of them. 
The total balance of your ABEL wallet will be automatically tallied from the Abelian blockchain.

When you run abewallet the first time, the abewallet will create a configuration file called *abewallet.conf*. 
This configuration file will be located at the home directory, namely

- Windows: C:\Users\username\AppData\Local\Abewallet
- Macos: /Users/username/Library/Application Support/Abewallet
- Linux: /home/username/.abewallet

These folders are the **configuration folders** of Abewallet.

If you want to connect your ABEL wallet abewallet with the abec at one of your mining machines, 
you should first configure the abecusername and the abecpassword options in *abewallet.conf* before running abewallet. 
They are the same as the rpcuser and rpcpass options specified in *abec.conf*.

```
abecusername= [rpcuser]
abecpassword= [rpcpass]
```

In addition, in order to interact with abewallet later (using abectl), username and password should also be configured, (any username and password is fine).

```
username= [username]
password= [password]
```

In other words, abecusername / abecpassword (in abewallet.conf) correspond to rpcuser / rpcpassword (in abec.conf), respecitvely, and are used for establishing a secure RPC communication channel between abec and abewallet. While username / password (in abewallet.conf) will be used for establishing a secure RPC communication channel between abectl (to be introduced) and abewallet.

Besides the configuration above, you may need to do a few more configurations depending on whether or not abec and abewallet are on the same machine. But again, we do not suggest you to run both abec and abewallet on the same machine despite it is absolutely feasible to do so.


### Abec and Abewallet are on different machines

If abec (full node) and abewallet (ABEL wallet) are on different machines, we also need to

- specify the ip address and port of the machine which is running the full node, abec, and
- get the RPC certificate of the full node, abec

To **specify the ip address of abec**, add the following option in *abewallet.conf*,

```
rpcconnect= [IP:PORT]
```

IP and PORT is the ip address and listening port of abec, respectively. If a port is not specified, we presume that the mining machine abec is using the default port (8667) for the RPC communication between abec and abewallet.

To **get the certificate of abec**, you should copy *rpc.cert* from the configuration folder of abec into the configuration folder of abewallet.

After finishing these operations, run abewallet as follows.

```shell
# Macos and Linux
./start_abewallet.sh --walletpass=[your public passphrase]
# Windows
abewallet --walletpass=[your public passphrase]
```

### Abec and Abewallet are on the same machine

You can run abewallet without needing any other operation. 
Abewallet will automatically access the RPC certificate of abec and connect to it.

```shell
# Macos and Linux
./start_abewallet.sh --walletpass=[your public passphrase]
# Windows
abewallet --walletpass=[your public passphrase]
```

Example:

```shell
./start_abewallet.sh --walletpass=123456
2022-04-16 12:51:33.344 [INF] WLLT: Opened wallet
2022-04-16 12:54:29.015 [INF] ABEW: Version 0.9.6
2022-04-16 12:54:29.047 [INF] RPCS: Listening on [::1]:8665
2022-04-16 12:54:29.047 [INF] RPCS: Listening on 127.0.0.1:8665
2022-04-16 12:54:29.048 [INF] ABEW: Attempting RPC client connection to localhost:8667
2022-04-16 12:54:29.378 [INF] CHNS: Established connection to RPC server localhost:8667
2022-04-16 12:54:29.917 [INF] WLLT: Opened wallet
2022-04-16 12:54:30.939 [INF] WLLT: RECOVERY MODE ENABLED -- rescanning for used addresses with recovery_window=250
2022-04-16 12:54:30.956 [INF] WLLT: Catching up block hashes to height 6, this might take a while
2022-04-16 12:54:30.965 [INF] TMGR: Current sync height 1
2022-04-16 12:54:30.973 [INF] TMGR: Current sync height 2
2022-04-16 12:54:30.990 [INF] TMGR: Current sync height 3
2022-04-16 12:54:30.999 [INF] TMGR: Current sync height 4
2022-04-16 12:54:31.004 [INF] TMGR: Current sync height 5
2022-04-16 12:54:31.034 [INF] TMGR: Current sync height 6
2022-04-16 12:54:31.036 [INF] WLLT: Done catching up block hashes
2022-04-16 12:54:36.374 [INF] TMGR: Current sync height 7
```



## 5. Operate Abewallet using abectl

In the abec folder, there is another executable called start_abectl.sh (Macos and Linux) or abectl (Windows). This executable can be used for checking balance of your wallet, make payment, and so on.

***As of this writing, only balance checking is supported.***

### 5.1 Check balance

Like Abewallet and Abec, Abectl and Abewallet do not need to be on the same machine. 

#### If Abectl and Abewallet are on the same machine

```shell
# Macos and Linux
./start_abectl.sh --rpcuser=[username] --rpcpass=[password] --wallet getbalancesabe
# Windows
abectl --rpcuser=[username] --rpcpass=[password] --wallet getbalancesabe
```

*username* and *password* should be the same as the options we configured in *abewallet.conf*.

Example:

```shell
./start_abectl.sh --rpcuser=username --rpcpass=password --wallet getbalancesabe
[
  4508,
  2971.9892438,
  1536.0107562,
  0
]
```

From the top to the bottom

- total balance
- spendable balance
- freezed coinbase balance
- freezed transaction balance

#### If Abectl and Abewallet are on different machine

If Abectl and Abewallet are running on different machines, you should also

- specify the ip address and port of the machine running abewallet, and
- get the RPC certificate of the machine running abewallet

To specify the ip address and port, add `--rpcserver=[IP:PORT]` while running abectl.

To get the certificate of abewallet, you should copy *rpc.cert* from the configuration folder of abewallet, and paste it in any place in the machine which runs abectl, and add `--rpccert=[location of cert]` while running abectl.

**Notice**: We omit the above operations in the following description of Abectl.

```shell
# Macos and Linux
./start_abectl.sh --rpcuser=[username] --rpcpass=[password] --rpcserver=[IP:PORT] --rpccert=[location of cert] --wallet getbalancesabe
# Windows
abectl --rpcuser=[username] --rpcpass=[password] --rpcserver=[IP:PORT] --rpccert=[location of cert] --wallet getbalancesabe
```

Example:

```shell
./start_abectl.sh --rpcuser=username --rpcpass=password --rpcserver=192.168.1.3:8665 --rpccert=/home/username/rpc.cert --wallet getbalancesabe
[
  4508,
  2971.9892438,
  1536.0107562,
  0
]
```


### 5.2 Unlock 

Before you send transactions or generate new address, you should unlock the wallet first.

```shell
# Macos and Linux
./start_abectl.sh --rpcuser=[rpcuser] --rpcpass=[rpcpass] --wallet walletpassphrase [your private passphrase] [timeout]
# Windows
abectl --rpcuser=[rpcuser] --rpcpass=[rpcpass] --wallet walletpassphrase [your private passphrase] [timeout]
```

**NOTE**: The unit of timeout is second.

Example:

```shell
./start_abectl.sh --rpcuser=[rpcuser] --rpcpass=[rpcpass] --wallet walletpassphrase 123456 240
```

This means unlock the wallet with passphrase 123456 for  240 seconds.

### 5.3 Generate new address

To generate a new address (to receive coins)

```shell
# Macos and Linux
./start_abectl.sh --rpcuser=[rpcuser] --rpcpass=[rpcpass] --wallet generateaddressabe
# Windows
abectl --rpcuser=[rpcuser] --rpcpass=[rpcpass] --wallet generateaddressabe
```

### 5.4 Send to address

Since the address in Abec is very long, we cannot directly paste them in the command line. Instead, we should create a file called *args1* in the configuration folder of Abec (this may change in the future) and add receiver's address and amount into it.

The format is as follows.

```
[
    {
        "address":"addr1",
        "amount":700000000
    },
    {
        "address":"addr2",
        "amount":500000000
    }
]
```

Note that the unit of amount is **Neutrino**. (1 ABE = 10000000 Neutrino)

And then we can send transaction by

```shell
# Macos and Linux
./start_abectl.sh --rpcuser=[rpcuser] --rpcpass=[rpcpass] --wallet sendtoaddressesabe -
# Windows
abectl --rpcuser=[rpcuser] --rpcpass=[rpcpass] --wallet sendtoaddressesabe -
```

Example:

```shell
$ cat /Users/username/Library/Application Support/Abec/arg1
[{"address":"addr1", "amount":700000000},{"address":"addr2", "amount":500000000 }]
$ ./start_abectl.sh --rpcuser=[rpcuser] --rpcpass=[rpcpass] --wallet sendtoaddressesabe -
```

We omit the rest of the address for simplicity. This means we send 70 ABE to addr1 and 50 ABE to addr2.

### 5.5 Recover the wallet

If you want to recover the wallet, you can delete the data (*mainnet/wallet.db* in configuration folder of Abewallet) of your wallet and run

```shell
# Macos and Linux
./start_abewallet.sh --create
# Windows
abewallet --create
```

Example:

```shell
$ ./start_abewallet.sh --create
Enter the private passphrase for your new wallet:
Confirm passphrase:
Enter the public passphrase for your new wallet:
Confirm passphrase:
NOTE: Use the --walletpass option to configure your public passphrase.
Do you have an existing wallet seed you want to use? (n/no/y/yes) [no]: y
Enter the crypto version is:0
Enter existing wallet mnemonic: biology,hazard,sudden,dignity,drop,jealous,butter,believe,answer,enter,practice,scorpion,health,tunnel,rival,vault,neutral,season,proof,must,path,steel,final,female
Please input the max No. of address to recover :5
Creating the wallet...
2022-05-07 19:55:01.548 [INF] WLLT: The addresses with No. in [0, 5] have been restored.
2022-05-07 19:55:02.282 [INF] WLLT: Opened wallet
The wallet has been created successfully.
```

