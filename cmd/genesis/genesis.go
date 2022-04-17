package main

import (
	"encoding/hex"
	"fmt"
	"github.com/abesuite/abec/abecrypto"
	"github.com/abesuite/abec/abecrypto/abecryptoparam"
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/blockchain"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"log"
	"os"
	"time"
)

func main() {
	gensis()
}
func gensis() {
	f, err := os.OpenFile("genesisblock.txt", os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0600)
	if err != nil {
		log.Fatalln("error open output file")
	}
	defer f.Close()
	//seed := []byte{
	//	//0, 0, 0, 2,
	//	219, 217, 91, 2, 159, 136, 1, 196,
	//	124, 21, 172, 45, 38, 93, 166, 104,
	//	63, 44, 77, 35, 189, 247, 110, 45,
	//	52, 145, 117, 158, 38, 15, 152, 122,
	//	61, 254, 149, 166, 25, 239, 148, 229,
	//	111, 42, 136, 249, 231, 100, 67, 134,
	//	20, 80, 87, 78, 169, 196, 253, 137,
	//	98, 107, 133, 174, 161, 254, 106, 236,
	//
	//	219, 217, 91, 2, 159, 136, 1, 196,
	//	124, 21, 172, 45, 38, 93, 166, 104,
	//	63, 44, 77, 35, 189, 247, 110, 45,
	//	52, 145, 117, 158, 38, 15, 152, 122,
	//	61, 254, 149, 166, 25, 239, 148, 229,
	//	111, 42, 136, 249, 231, 100, 67, 134,
	//	20, 80, 87, 78, 169, 196, 253, 137,
	//	98, 107, 133, 174, 161, 254, 106, 236,
	//}
	//_, err = fmt.Fprintf(f, "seed = %s\n", hex.EncodeToString(seed))
	//if err != nil {
	//	panic(err)
	//}
	////retSerializedCryptoAddress, retSerializedVSk, retSerializedASksp, retSerializedASksn, err := abecrypto.CryptoPP.CryptoAddressKeyGen(seed)
	//retSerializedCryptoAddress, _, _, _, err := abecrypto.CryptoAddressKeyGen(seed, abecryptoparam.CryptoSchemePQRingCT)
	//if err != nil {
	//	log.Fatalf("error in MasterKeyGen")
	//}
	//address := append([]byte{0}, retSerializedCryptoAddress...)
	//fmt.Println(hex.EncodeToString(address))
	//hash := chainhash.DoubleHashB(address)
	//fmt.Println(hex.EncodeToString(hash))
	s := "000000000013a6c9b4dd88e61f082f9490ca71843a3b498c67d428c0ad9131afe4ca6b7005d4366ac4b0be33e49760667005bb877f4d7b4b6729317768161d88e0edd1f10225859e4bdc565fedcae7bf63f4682863e21868606d250cf7e343a43b7c1281819834debae4da4185a91603518f99c538a038e05f3d0d884ea933120c6bd4bb5b58eab52b7dcd25d8b684bce25de6305e9b745147040fb6375662e45a1863b7ccfbde08a78e78e4de589713999c825377e9a66b0e500be267cb88580a2775edab349fcce996953473e758be509e193cc9d7b68a675c5e147b7febb6ad82fef326b82f23ca1e6b268eaaa407212842bcf19e0285e21c32a11c053086999173ebfc2fc57d7e0ff74e6f166874b70c297f37e35ad0877f2a4161b5a2212851e41d1cd6901d0a97b247cfc71fcf7fe238a9618832322679571f70c8d3508e5ddb959858c854a8f8231ddb6fbf8678e600ed26deefba0f8437bda409379e86ef4af705412d5e39c785e9683454ec951fc30b7359b507b51825f1faca1d4de97163596d469f7f4867438bf3cf719cf11dcbf4e872b94e43f92593687c4b4aa54de7b04c41d565d7cd4e02e900b0cdeff886e5b35c3c3780c8a5cab70f15494b074da1480c7b4dce4ab3362a2baae9f40452f8e5571212c33dbbae0ddee1ae3b9db7fb902f3daf384be3e7039b82f3120284304d7674c7e2bcec6e6220b7db621124c7cccfb0f5c459dee567236e18dd011269993e112b58329fb5bf6c39ea39fb6aaafc8ffae057532feaaba63a65402062d073ecc484334078c89c657129dd8f38c3e1e8b8fd837e80d6d09b8d5be10c5893e4f49e1502beec3b79488fb798b26c3bbc23f5dbd7038041dccbaa254bfecd0f8ae95086816759b03367b15e3f03bcd8bf93eca0e30ceaedf0e3db7244937c8d9cf36eb00f4ac0ad05b0e0562dc1893ed58b0c368bb8a8564321ae4b0a60ace144930be023d5619844d4716f947503fe0571dc866c7c7a2748be053c962794e47539545852fd01688154de1eb8038d1d86b5b553eb8f5fb94bf9c1375bd25b01c2bc21897d4ea0c9ffd1776ada8d1f879804439e1c8f48407e3a2fbbcbe6269fac3f9947c1877224ee254b5bb5d676b85a89bb932fd27afb4d1c80b9a593276f6c2d1df0f9ecf4727617ce650ffebe2853991b9bbd38b7898319d6351a74dbf52c26887dbba899752c080699c4b61407c9f20e68816e06c82d042354ad38b6106ff3c1fa7ce97851960e130d7092a1fcf48e4353a6106c5540a830680aaa6211b29ca5ea95065599fdad8ba90f5ec474cbb6a93318b9ab9a25fc59a3c4de6051b8a1f0a2ff7555469216f92dade7af2df22576893caf7506c3ea78ee2cea56ce2a7d9f520c19f265e32965de04467abbe9f91f5507d3c2cbf6641f75bb77d9b345ebb4ed79e7e11debfec74e84b43ca093ef245d5e6a2ce685b445dca11c21b5f4fa6c0e802bc57deb0ef3f272599fe46a0c100fa832dc9412eb0606421d4830f532b2e43afd6244ce4563d1f0696ca445874ff219cac21e2a06e5df66d140379d83cf92e13e536c74a9cfda29a26681bb07dee9f99e64fd6868f5dfec3d87c1ec5ff307f9d28f7bb7346260acb8b1768df5f41e5d297d1a8c3a850ab34818248ce378073727a69006778998384a8f176284ee65f70d3258913f3f299d291117332145a816677d761c50baa8502bbc24ab7ceb2e68fcc66f940fa9055f907e5258d694c186624bca5e1abaa037834dfb1a662f8d18b7d910b35606871c534131136354e67ffe405e4c6d78b78ba15101fd6e6f52d7370b80de0e114d7bd4c586396d0902faa5581f107454d80a24115a671b5e9e3b8d8d4f15241a23b1c7804d212ac80faa111fdd9632a6fbb43b9513ac7ea0ff1a6e128fd24edc738dd98c730b55fd3568f81f2ddd939e253723dbd3d819534a38b4665ea6442eb4ba4194fac6edf4615d76a669f8c07e47834f3b5ea67077361a4b6a5fbc5e05a0460d367fb1056aa6c4099bbffa1a03808cb00793036815b534058d7deeb0659bfb1381724d0960567b267e36869f22f07c6a092039e9292f3c445f25b2ccf73eab13f675aa26a0ec3388346f04d1d958cba45d9d14a6867e51a19c9bdf8ae32edc51225090c54a95538af06a1467014cc2bd6cee87dcd5c094c665340241d8cc0373b2af358d3a417383700b5838d8353ea58075c30ea97e9826157b45f9c64653d5beee03ea5b7ddfe7c717244de7a27a7eae98512dafac3f18fb936f559797242f725c6199e6cd5d949ffd78b6289978431a749555af9094a4b0b6c1deed86d0e065bad829c9349b62ed2dc061e3e14616ccf4a5d15946199c1526fa8c2e36058be17ddc31d33a401d77bd85140d08cb83daa31906cc7318f00c79867a3563333c8bd71d0ffd3072c00480402625ae408378e9f7a67f7bb321a86f3668fa23871fbe222b725bf216dba6c6bd9510217ceeea792417323d822c83bc4642a8a273b3324d89eb72f0a1c89c8b88bbc3083a334048f96a64ba66de81fd328c61845e8981dac7b739a3ba94572d8d9f9a46695074e023a23a3906ab5ee72c08deedf2e63eaae466d1cbb7d7bdb44aa2f20bcd5c3a89243f9cfa88faa21d63b202bf47b32e68fdda072f6e1cd304023309d1b38b104db7d5f3fa58f9d922730a2ad0d72d52d476eb0a000270ff07b5988b8f81c80160b4073df86873d390d27d5015d878e1d59498b0c78acf36c0c61eecc5c2f6b336a16a5a62454e7c9b931e7da74bc6cd2434e8c87aaf533bddbc343fbfcbbcd1db58fef2c087a5849b2868f08afb22e0c3635ec3890e5a23ef64f0481dfaf6f54d386da95713938b8cc78bf19aca7dac3a98e62c146195fe40705800e7ff582c819a06449fa5239c09443c84e266b86bcecbfdd6e2a3183361ce8566d723d9f9aa5c5bb812d06b17a97334ee3fa609e2cf978be5cb31ed496ccb2a3b9a6e91eff216c1517285ce6c67e705d517211f2d7367dfb33e5f284633cf0e4228e45819262cf6ad4d0f306e9b7a0df818f88ab843f9003b7fbad02fdb1956094850a8828aa6bb06824fc35ff08efe70ec3992642fba5f57f5a6b9458d47117e6cf935eaca31a15342d9e7881391d97485b2e457b7bf90e0efce9557994792bd9e729cc5cc5057fb8c0606b04a174d7225b1b63327cfa5d4030402946b134e9e890e6fa33e68534b243ff118d75fd7f729e1bb720b966f736f0db53d0a9f7800acabe02308b1d8ca66e297489f507349cc5b6b2fba135372040c84d3719542d1872757599cb6781848c8fdff8a2934c2f9841b9353a2d3ea416973689f0fe628112ee2bd12a6724e987343e46da8dba132b7c00efaba0f46e791c3d2b9a816362b9144cf813e8d9f18431afbaa3b0fd506840b4393f5702f69ab0fb830bae8134de342d3a8e98aad6f35990607080b9550168df49c6a2225eccc0f7fa7e4d8668747d3ed1dd6dc313d541c5ba4b5e383cea2c2b002abae85a4f23fd9d43d9a6a91f9ca41986294ec36771398c0e01e4f71a86b857bb9e796738b14e105a4eb97045d53e7b225da95357ab7939b9ed8491235532cf0d45b770b6d5c58645335fd7fdf48e1a0cb396e2bce72b8ff3f600fa483a3398af65418d9d797b6ea813b8588fb5ea08f1747ed3f0f5a0b1dbf28b777432d91a82ec9f597ca69ce192cd4103e89dd744bb3033f8715fc13927c93d2742c66f223e98cc7c567fad4c4e6958e26cc65ecc5380e1295b3a83382841273b11824c5b5bd1f2b641b7771fa3dda9143f4baffde648fef2ede058a601cdca04f92a3b79465b041d3b88b6d318f4ca8b86ccf746e942abae006dbbe6e7605f2ae7ee33a8a987ccb4d2b386a7e99e438a3dc1be4a59b3445b5334b555680259e8dee1aacc277dd56523f5b87c32a9ee5d8ec9689505ae8a61563985a635780ababe9a95487cd0f78c769800ed10b37bff7bd437b47e34a71dd2618d3be6d9b1ac42c100764984430bf76840ef2b1f7f40d47f837690ac9d3dbf08ef7c67ccc03a585a86dba66ecc043c307957cc0430bc5559b0f5c0923027e45c18170336baadf0072b852b609c9b354c9178f57af3633504f6096e0ff50d15d65b94cfa8c639c136d6fcd4377553a546806df8109c11c77f3a447e0ebbf7aeb14e7c73f8073801e4b4de8ecc33160a662a9cb865ce8154c7dc263e21b2783ad10babed955b5a0b81376b95dcfd0f5a0169ef445b25b6cfadd3d1bdc729355c2c521d441ffcf7927b0cc475f06f2cc3587028899136e50bc87f9c772671bd0f82ecbf4df1eedfec306b63e8498cbd1fb4d2455de30ae9059b67479c8f5cd93eb27cfd5852e9cdacf2bfcda80ac78f37d09fce57760282cba3d394fe4808a06457fca1dc53b833afa25c12a1be707287129734cce6fb53bf199e28163a1c05114c664c66c2dfd9e4aadb26d5839843b109bce5b706bf3afe2329dd7cc93721f84666b9f4b99e1afb7786f16c40cbd429560926a53a65a65ce5e0d4f6419d3fc51747cddb8961658c0d7834aa9cd49101db4e110985fe942f4f36af9a39154d6a470b1da61755688969542a9a07f70309ef168f7695eac23ee601cd93081d187e7e9cb771fe44e7f049d3194f1227e311d20a64ab2fc8e57dcc00b2f9b677eedb945be406c8e5db3f694eb184027ce4270a01d35f641e041ba2c1688682f94063315ee0511b004b52cf7d9d4a8eddf7444b02ff1ce9c704525062bda83c9af6a3592dbff2d085038e4a3583c39159cc0dc06e64e6b5d938ebd96bd7d03197b256246ae7a3dcd49fdc6e6a05045bb1099c3d2fa4838f6a549a4cae79f06550781dce8e2fa19c5f13869ac326c1ad71a33932d3cc1a71b5cecd54f9b0e62fea39cc5dabb9c69dbcb36b8d52f84531de69c19920297d0eba2fbf8016c660f07ad239069bbd2e3209507bcdb44c5a706929c9c2f25dcb8f1e6abc654891929dba1be4a3f383bb78304796d583626ed42943947610f75026aa6015091efa2935a2d137a2a9c800154988ed2ad1ca3a0a6e34f35f4f530804cbdc577931c97b5c503b015349c15653aa1bbc59265208d64cb38d72f2751aad53a96afc57d55c19526e74bd08313aefd786715e89f49dc73aabd5dbad9de79ff8061941528c2ed3d4a4d2627401180d45c9b5144558589a58a90aea7fea21f4748d6b504ce065820bd17d86269bf1aa511959cb8466fdbf0508f6f1bef335503d1aa17109b0a3c70c458129bcf0a427474f8d2517e4af418a8ee79ca00dcea87a5254369e25d596122e6ceb677920426e0961bcb7b523cf5fc5ec7a22ade32ce79379863094bd87aa9276246e963e4aeafa49e7b24471f5b9ddde1132cbd699de12db3543d00bf9923a54af4c8076961231fc75aa7003523f4ab18cf27cb1fbdb5a10171911384c22fb50981e91f297a6d0b790dbe6da284dea45bfcf9ce192f72dd1a02c0f5d9d834cda47c25e0f2a2743e13614ed009e76d4b9dfaa713c1e2bb36aec72cbfc82d7f319e1fc93a5c05ee84bf3d4a5b5ee1da7f241f132c1e64021b1a1a26181e8d17bf961b793bf3ea7067d5124b5c9e8e0faa166cf0699b2d75cb0f5641e77ec38bf9fe9d1ae30b4d57d6ec4ae72e64237a3d73d5de56f1babb88617865d625cd07402b27912845df15f4c4ce08264671e3bc9b3456f26b499b81ef4637625413e87bdd14f91057b1c2f236e9c8ad346714dfd6a373875ef79b3b9bcb8cc75843d20cdde29204fe9361ed655408c4325393fd063c5c601a23b0c020024eb078f41864f06a8b69567e2950b9944fc3536c5eda6f336a2a149f67ff8b831560c99ce4a2ee7cfafdc01d5e2b39ecb6fcc8ee625c120c7e18d07fde8084e251d36c13ea9719f544772227dccd01663e3260d5eedad8ffca579d4f8fc471327cdf734a454ae914639cf63f37f9b09c53758e0b8e7400944246de804913bb6f196cabf70e05a07b91d72e59b341140dd1028611628c0845f02f835568498aba4100a23887c45f10186993f35b2e177d1399824e3457fbdaa7b861aa71aa213e596dfa2a834b594c5237ef88e09ee079d96ecd63030de6083d3d10388a57f1ff9c79defde5b7ce7968c4162964ccfc15cca2eda0b25051c477e7f2ee909c5e422ff3d5d3af02985531336f913efcc59c2898c12f1482f131c8567ef4ecf52a790322909dbc045cddb29df30dcc124ac139ce6504fe23131518b5a12421aa03126da64a2059b4f731d319b1b9026087ea2a5fdd5d02fc9fa8973862100e6fccb1c0acc05136ca7b266bdf3e39f0b00059230775e706ed05ccef43c47026a89bae58eafb0105f9b1fc4eb570c41f71be4fa654d169240e3eea0d2870bab231817cbf98cafd8d2e618e7f955bc62c14338e191f2afbde54bfa3bde03e3646234925cb48cbcdd250bf50fbef1d3bdc551a0711e97fb776ef3d5be165a5e4a34cad3ae858233cd17dea3dda810d35be87f762a8b76b2772dfafc94584245f728f65b1820bbaf345118bdb692497aaad34044eaebfd20da8e1ffe97172082d6073e58ec3ef8dbf837415f386001b505f1c5aef317f3568afddc841113ac121c6aeb3948d1465b8ee7db2028b004614d92765d24dfc38ebc9db4332c3129ccc4c7bf53c01020df3cda61bb55375ef01a495a447ed2c861991a1f3ed40b975d68b652bae4d1613f58fa37f4cfebbb2c9bd0fc7bceea60e47efb3efa29a13dfe0eb59d250e9fc7a9d521ee5931327ecde3a43535003d3b18318933ea164a9f88aac01414bebf49d9b3e4e29309d94ef826ac6b3f6f9f946561a75d3f3aa5fea2301d0e1f3cecb0607ba6eb70d1824afdc869a472f244b718ae6044565ce2cbc02b533ad37937e31af3530a24be59965c00722862456df7111b9233c00ae9ceb2071e79509ff04f0df8587b3aa58734c1461eb05fd3fee36394fab7a46640c4a294a91f86dd1d989f6402581475baab0246132b47496bc74a7cac834400840537b48d1bc4da8f2f1866eb87580b2e61112930f2f33628795dd142cde1775c725480ed8c501b272395ef67be39e65be57b1c10c823ef183c04b4ec2440d3dce48ad4bb8dc68c9d370aa62c3288ccc4f3391637117ae2fce8bb9e0a2d39ad1d80c89ed98eb518caa04350a6713207800eb84e16321b4ffa21cd59cebf5eacbac573bb81da58362c59a9f1bbc2cc9a5af49c30d79c9ea3c4f079c0c9cbb5ee833b4995f6b853f5381326b99f3b56d268ba4097f902ff701c0a43f155a54862d03ea735e446d247437389584f1dc677b018369a0c192ab1cccb5dba2def6d03b8b4229a4bd71b81aa80f045feca755e91800699d0ab7af1991e67bed4ea50e79383b3b14994d08d40b3142079f1fada8980eedf5cf0d707267b33a37a0a1babbca4c0d00ab4ea0e58d32af86dae1567fb5b2ce3ad3ab34b78a29f0d9decb83b5be9fabceb13533b0699b8dd8b28b3964166efde76892f5e19c8d4a671618ac429b9c856e0ca96ca32d87c33d3da33c99001896db2ed913f9fefb78827ab372fe8a152473d55b05c5884bb90414222cd3fbb75174154ba073a1b105e3d7a58db332a4d324a8b171ab7f58f1a4b5f4fc4b0af80844c78e19e50b5bcf7e5b935369f8306a9f24663c8de44427dd173170fdabbfdb49bacc59e657ed385cb063fa646cbfbc9f3a31db9303022bb0cc67d3f5fa1d625dcae2f36c8a1641aef2e8413e9dcf7dd25a780e32a591d88026a6931e92b7bb831acaa4c497b835d2d9e81a3d723e420f686d6ba5204aec7a38302dbde91abead788e44dc876fc6f1e3db80ea846c067ccd15bb9c865bbdae0c9689d11e3ddd10f85025349f7e2327715eddc412ef66902fdf865048a5620db40baa16c033a75ac61583fe6c1b25688eb91987e6887afd42916685c145a50e8642e9040ff5054703f0bde79538fce36453e0d6fcd59615575b13b548078112e39b66d7ecfd812913c798a46ea98296f247d985c749a13de8baf6155640c8ee5209bbdab1856fbd2add7e0f1a717438261cb0ec1e95b3ac2e95c58df97ed31b2470d15bdef679bebc6edf3d9d442d87b73a0e06e532958f9ec2470d14a8d728f78d52e0a4cd4222a02ff681394da07aea12d65a45d501e29d410ca8f255734f5c17ad2574b24cce4f986aaab5434e0b20454f3cb47e53f5971e8c0af1d68507b5f5e25abadcd8cdda1652a533a6b793a61fb3371ecbdd18034e03e5c0d114511277a4b0960692f8021e627eb82edf3c098a740cb949b060b15e2dee504a924251e74c66a7059e89cb9ee06e314bd959bd0b10127552d847a0176bfad16565f512a354b32928d2bbe608f3ac230a4c7fe93284b7b84e3db67d2038497d4373c7faa189f9bd04ee7fca8aa7eef07ec9aa58744f03f2d0eaa83e925e4a897322850025d7f3be0ccfa18740a6f91f1c2b220cb437b13acf8abef1e994b76d8e023da4d03d24e9b00aa80132f20ba35986fc12b72f295579a91ed70c501173c2d581deaf5abdacba76eb9c7575b1a883270fbf77e5ab26607b93b06dc61d5f70be2670f22814d44037b43b992cd627f6a30276f0a20b2d48e38d2452d9e41e359a472e46811b6a36e34a8bfb26e68fd1d575b1168660d87510f7d0925f6fa74011bad991f358684f7c2ea20539f7279e246a215e7bfae803bbe86424d615cba4e63ac860d6ffabbcfa1f424a03421cee7d6bb1e3faa503a9018dcd892e21992c6a0dd8db7cb3e17ccb41ce6ffc5446cec97db1e23e80fad71c865bac3a500b165cb41d8f64d0eda4fe40bf338b58c16fe47c4a4031d28628dad10fc1e3a7ca14d52dc185bcb5a2cf61c43da624a27afc6026e9a7467d5e5494b73c37bc4bbac55fc75576224936bf5be1349b6beb15657139ae1a996d1be8c44a5b1faa4ab2a39396e0df9bc000bf8792ea2a70b580b4c4c856c4c4f7d7883fa58e2b2794f234adf48589fec96d81632f8f2759171c7ac45ea5b978dbd774f9bda0c969adc7d61d56c0faaad35157e198899def594a4f392882c9e907f88efa66a42d25a7b9b42eba6a9d545b26c2d376313e973b241c20668a0263c7997c935cd719834809f65f44e0f2da80b6a44cdf56ec71152527b77ff9d6e09800d4ea296c0adffa8cd9983ca5339a9732453c095fc4365fc5d5709759f1dd8397a4a327661c3deeb591809f882930677cc5aecbe0b36e0126573ab018e52c37b87789afbc1e193fb2ec8c84d6a7a4502be547b078522734ee3fcb935f75abcde9857c0a2c11c67e3334fcd2bd11a6dafbcbbc3d92af8eb697b194571d64c393b5d3805548750ba7d008569948577bc8ceda14602ee56b3f2b1a7a4a66b82c68b80505d5198ae75e4250b8e99479488eeffead70b6f6d1141147abc0ce47f2a4240a5c6e546dcdde4c7f82181b8d72e1f461def0a683bc70a7417308ff9ea3b78b89a308bdfc08bcf09de12b9a9b12d35da2e08af97486f3b021fded385c672d875215d28dbfc8df1324b94a0f1a98243fefd43ca83a70555d41806b6450696800ecacc63cff12b2781086b0b50777969077802a00c09ee749281f5663ead0002e3ac5ee9d4c5063bcf9dd48b892397d96f4abeab45f837ff8852d8418d5e247a9c6143d34284d6fcad4a870f76a64a950469b3885fc384fe3a1c9985c2cf827bf5bfed5807c5cbe8e4aa5765c641a377ab7f14aff97c08abef293c8ea6d7fe43a081396204e904b10e44cc86962adaf7b7846d87c779c0f9f622240ca79dc7d0b0e3ba166515af5a05ee7d9cc2a75a23c477c4d78981a4018fd512ce4dca13d646259106b368404287d72007799ea3e724fd41f1e75507bbac81e1d86e3d996c0939f940e5ad3462170379575b03050655388895c2ed99c6c9052cea1573c9a8f04dd58a3c2f0cfb1e457c729997fabcbbf02cb5ee18310135a185dcbdcb8074cb772d1b92046307efef36ae1d4dd8965f5c5dcc179d2b7bb37a8416b43363c6b93d01973caa882840543343f1ecb34eda791dd7436c31be0849ece2271b5cb6775c6c91126f7caa9d0e0939aa7caf55e229784c6dec63a743bbad40a9123a5d31d801d05b756bb6b50f383cd21bf9bcf66ee96943306d274b7e6276876acdc696def1ac17688d971d587594f5c01a813a2b67800e7135a0bb74eec9385af23bef5faf6bb3b313d1264a2e4e3977701c2b942739d1a3f4ec5264bc3a68ddf745d5e153f848d5c9abfe67b5343230bbf2eb352c2f83033727183fba9201d3711b8759287f106b0254ce1722e01ccfdf47be62d0d1470f3e50ba92b71e42774f96e0d57187a9dbf6f039935f1a66a9d1bfbbc3d1a6147f803683166b15bc1b66b164cd47e9b242d6d574cc30b37cb4c0d7c0bb0e5f69e0d8072245d1e626c1e74c3f2f26d6a60751625f84a0c11acda64a7b2ae461bf8e879adff43d5a9c8b1f493121b56f46ed8e542cf01441e3e1ec693ae748162da1a7d1cdf33eabdacc2f0cc67c4e4d3eca8cd7b27003d85353ce84b8f29b3f8e6f975cf6849abcc60c81f438010ab55d7dc712acad5b5a87914a7e0b1ce02bffb7e938554b947cbbcd69e75f05b91d2e7c6e48efaf5482af60a21167f82704b275bb917ebfa913a09ed80f97195678a7f4373e3f59b51c80b63db56d8e19075445a2878703ca58c423d3c06eba4e1a5036e46bade8f027239940971ce0213936dcdd01fa4d28c24c99a2a8165bd5401e77a0892231fa4468c46c7e58c08d431d72fdbec4469dea8e81e7f18618216029487fb45d7ac5f367880b07eb920c7c35ddc9556479136bdfbf28909c6717f83227b80909ed321f93b0f96ca29355b19db7b8ab19abe1101c7885aedc9b2cb0e9bbdc651b3e3c64a2a76814a51bcb3c86c2ad02611fc20cb0868906ac784451a3f6e4bd7b20bbacbb6517cfa27cfcffdcb5473a669fa55e7eec6ffde15ffecd71b5616dcfbc3316d080114b27952ddb2529b78cbf259626c86bdf1b7aa61fef5f5423c53f68518444dfbf718bf280face09dd8a19ecbb0f55a0186fdcfa9c97a3e1ed0d543a7aa1ec2c657601bcd2927518cac56b40635deba23a053ead076aba48569f6610b79941b080ba6e73846f43b4e077133d1e2e48f121ab4b715395e651bcf4dc52ae2ff42c9e96a0c778d21188d9e29c2b4a6aa4f5c2e73225860b4369efee635261b919a24020f0b1981d12fb46f4fb5c0c2f5d61f06d738b15b240c29964dcb8efb3ba0c40c27539c96b5c01e77f9b4a8889fedecc0d80a0af744bf158d8426134ad2e46587c4e279b1210914dbc7a093e06431087ee6d9f9506885dbcdd6ab5bb8e21e1bf58634393f73c55344b4edf679e48687a653d9e673fd78e74f6a74c4980df9318487a63cac44e69dc313f30b8e8f2d8b80b7d06dbd6d10a10c2a110e1cbe40dd24c7c00618ae223f4f317f72cf76742993e2712a9ee01094336deb8c852284771b9fd123f507e00224aca9fb8e50c72be0f198b5e0f7e18c7325dbf6018ef1d2a5e112dd35880e44f839353fe832d2425cf11bfba66a651e01c6934e8ec36fb2434d43fd43c2335b5c67d14deaeff2691b0374bb3be78059265a5f3eb29de71127f9745ba934c79da9b94bf846fca321d3a897b677e2cd7d00b74c674a534560abc27cbf4f4507cddf2b6f83e940f8756bd006b8ddf81b06023544a11174a4799528da0fd14f012981149c12b81a3b943d96f5e44fc0724886aa60a8ffaa8c608f7d03748f381410394a9ae5bde997999607f485c1f96ffd989f1bf42200103b1dcf2db9e80f17705e6a8f9b3a4d5af47b0ba16b5161c329d234f99fa1b526f0437490d4871d045fed3ddf4c1c016210ca309766f51c9356d6c45a00d2a3c790757494e68244efb1d5f43d2fd05626d0a15035bd195898172cc712a9b1a694af26ea5a5c528021419bc72e757e2b90f048a66cd48cba19aac1661d06c7ebef1b3068d11f5852ee1232bfd549cd72fcdf5f771b550348d49da55c5fbde1bf51fcfba508de4a2edc4a2506182914f778236dde0c9f293679a3563f44eb8b96f0165d86959e5ac72243bffebf3af19842bf5067ffe22754f042e394040ae623d1633cf116d96edd79ef0affa936b0c0e1eb03a043863669e7b9cfd036c1880300da5a69ca2d6dd691cfaf02e311b8295b326ee3b9804e9ff5e063df77b5f9fe7eb0cd691bd98d6d310682f13a46d265da7a34de842fa3b95826db06554fac611a1d802057ec194b320cc474481fae1c2213b7c8a6a9ae13b5acff6f0a6463790502d7c1ee45fe55509fb6f0ea42765916d00bb160d4a9eddc2eee2bd17aa91837c54f717b1f7b19edbc44711ba968c043f36321e994d4b073245ec7dfd954c8127613d8bdfa646092ab424cce4afe3407bb5cb53f6f413bf87190c99489bee383285636919f5ad8736b6f36762091a13afbd23180920e2b85592da3b8954a35af1eea5100ebf5112dbc6afccc681399ac243c7b54024deb49ebb1cdfcec86a234a02a44c0a5fce81e8a2de7e333b5ebfe9ebaabab2d935dfd6006fc888d31d056fbec0307ad86201e298ac89632a0c4e356c8d186367902c0052b5e06d0f7e79ed4afcef75579d2abe0cb14a60b715b360a992dbce6541e9f80fbe0c0f772e0b3d46ec2c11244ecceb599c4180e8f2d2afd482ef6c21a72a4edb69b05db4bded495076c139639ce998d27bdf71263f234672416e26206c65f3e9882de2bfac1d40f9aa71a34cfc37edd35e0f1df6a8f76666cd467d92707b6bb666ccd2c94f1f66244b1f9c9a3384b81de0da1c409421112afee52bad0a26fe08085ea2b1242a142d4d7c684ace8a7ea71579fe1db024bd9832bd3782d494c0d690f1f37569225b93909f286d21432e267ae8ee67c1bc7d283e98f04774355a834dd2580690983bf834dc3e7b4ab2681b92624a3ea1576d84e864b8e7c3a145345f9199b699c91080f1804aab84c62f396e5e8d57d0253dea4bb17f89d1fb903657ee913fff226a925456817d70785f5b65e3fa5051e45865a782a9ef2bfbdad2243d1ca9a2e414b976222f67dd7250d1928e51c501f812eee4174fb77c2caaeaa2508e04e7c29a36efe8f4928aa370fc6aa9148cc16a8ceffb614a77a6f72b3d777de97872ce8a31ef9d116b2014b2731eaeef68456376b1dbf0e4bf4648cc753d6282317c8e0fab930ae1857067d80a92aa80bff03447c747d728c1cb8870fa6ec8197617f62e9174d53c9e2b48e5bee374926e18d62d913640e8df2eb078bb7e03147321a5a262bf7ec8fc05086fafde01517fa635026557a7583feadbe2515b435138bc98047635a107484971947abfaa12f10a9550a802561ce796d7ece9d5ad004e624b5b5156905c613de59423c1031004aeb10a79ce65feb6558c0c31094329222b8979a2b280a9df13be072ca9e52f3e37baf3a907dcbeb07c6db0bd71f2801000000eec2502273014531cf5374bd4b9abb1252626889914ba36a6154694d331dd7552c0896b47919b71bcc1bd92c58b5ab3cfae66260155b187355024658f9082c61b43b19888ec87a4a0ed015aba4923a643df67c3271d3c4686cc05cd59085b128ec9a7e1566637bd5bda7d8adf4cc7632ec5ef92b074f33b6082c9c16675140d5961e64cfc6c294a358467dca9a6fd38c47056f6ae552215c2c42eb29a5d3819578aa1380774430965af38bae69499328a63544852487667d177db7c27e58d55baf2825267446b8133918b997facba8ff8506c824a076e1bbc1dbb0e418c8a1b8742d392847d10d0e465cfbf972e6c4c4df8cba1115c6b04b3f8ff677a0f6779a65592131497cc889a5a0b309f0006d049336b3662ef86f86b52dc330b249364b6dc5c3bc768ee576057feb5c62a07aec0192e12cc7acb8a0d9c4cda6010ae62181f2d50a2a63cbfc2710377877cdb3b16e859cbcf240cb0c31544129e99aab6011a86c839d21124211e547c55283a2a3c890aa077dbb5782a670b0f4b566592c1f4397b1963baab40dbad8b155d406fa5b6c18b4063d67ace01a12a3228c42626c52123b53f4aab2c162119c4b088b477192bc7ca581a175546d0b25870661c74ba8ecc6b2e16b39af86aa6fc6908a875f802b5ef8ab52395b384c2955cb32814f5bb339108673f455a393b08622373a5bccbe5aae30d28cb7887ed567b5d6c567b5facac396cb96ea0006466e87a59f624872373b16c025816056b3fff5036045c8709ac6fc389ed6fa8814f97d55e39f98f054cd55af965966d87305d7f32081f18fd207aa92f144c56cbb4960ca60f370e7ccc09a1c108d23b8ea7ba9f4624caf02b5e3a54b46b24ec7d2946966c5375a8cfc935be5116fe5860ba27510b0e87349a6b357a74246638e239604ab128bfff0090547b9520cab0ba9a5d4772ee7b96bf131b803b28ab9362b31316cc9c895d64c617b7cc3419987e4fa16d6e0101840b6d08230b2bc3a450b72a7277ccb042118829cacc951dad835b658ba47f14ae1878d15e0cca7c20494b690004a7e7f8ca19b68a11130757db99b421044f7a647fbd39600705c227c9c9d03377de89bb9805a190c4e0c979b3716a3f2b55e34065609c8c92e043591656829e55a2747c14e5989e0607da133045dd2aa50e41884ba290a624ba419cbdc5c5264fca28736819ee0a3778aa1a798237450a1f379084e438eec8439b6975ecde61a4ce04860f22154a78a8de4becf69a4b2c992d55ac5e8828093f3c726a21102c5959fb6b4b17a93bbf1b21890391528097daa6deffc21d4832319f850b6937b1cbaa48a4c831d6a0068080c0d708f53944a518430b4d81a69661149179ee56835aa487ca0b13b58399dffa15e1e33b990e840036514c6394c65a22d65509fdf824c120388ef89bdf54805e059b8df3549ca72607da94a37242de038b9be407a5af7285fd591d9a1517c94a263135c35922f7b8b8f7b2c46418ca62c17b51006abec633e3cdc43b42c9ee07780219b7a0d94395c061f3bac89ea63a26a225465a95f19829bb4373d7f7760fd57201fcc6fded209c71480f6f28dbcf2235dd17d91a5a48726cb1a7b3296f445f89764eb23af59a93dc668d0fe2e56c50b07058e0723a6a6b2b3ba467b505cce12e6b056b517fcd998e5bf10d0849fcc4c431330276bca820591c632fcf028a7e6b79953ced5"
	retSerializedCryptoAddress, err := hex.DecodeString(s)
	if err != nil {
		log.Fatalln("error calling hex.DecodeString")
	}
	retSerializedCryptoAddress = retSerializedCryptoAddress[1 : len(retSerializedCryptoAddress)-32]
	txOutDescs := make([]*abecrypto.AbeTxOutputDesc, 1)
	for i := 0; i < len(txOutDescs); i++ {
		txOutDescs[i] = abecrypto.NewAbeTxOutDesc(retSerializedCryptoAddress, 205_799_813_685_247)
	}
	nullSerialNumer, _ := abecryptoparam.GetNullSerialNumber(wire.TxVersion)
	cbTxTemplate := &wire.MsgTxAbe{
		Version: wire.TxVersion,
		TxIns: []*wire.TxInAbe{
			{
				SerialNumber: nullSerialNumer,
				PreviousOutPointRing: wire.OutPointRing{
					Version: wire.TxVersion,
					BlockHashs: []*chainhash.Hash{
						&chainhash.ZeroHash,
						&chainhash.ZeroHash,
						&chainhash.ZeroHash,
					},
					OutPoints: []*wire.OutPointAbe{
						{
							TxHash: chainhash.ZeroHash, // empty hash value
							Index:  0,                  // the index will be limited in a special range
						},
					},
				},
			},
		},
		TxOuts: nil,
		TxFee:  205_799_813_685_247, //as the vin
		TxMemo: []byte{ // "Abelian - a Post-Quantum Blockchain Ecosystem. Hello World to a Brand New Generation of Blockchain Era"
			0x41, 0x62, 0x65, 0x6c, 0x69, 0x61, 0x6e, 0x20, 0x2d, 0x20, 0x61, 0x20, 0x50, 0x6f, 0x73, 0x74,
			0x2d, 0x51, 0x75, 0x61, 0x6e, 0x74, 0x75, 0x6d, 0x20, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x63, 0x68,
			0x61, 0x69, 0x6e, 0x20, 0x45, 0x63, 0x6f, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2e, 0x20, 0x48,
			0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x61, 0x20,
			0x42, 0x72, 0x61, 0x6e, 0x64, 0x20, 0x4e, 0x65, 0x77, 0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61,
			0x74, 0x69, 0x6f, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x63, 0x68, 0x61,
			0x69, 0x6e, 0x20, 0x45, 0x72, 0x61,
		},
		TxWitness: nil,
	}
	genesisCoinbaseTx, err := abecrypto.CoinbaseTxGen(txOutDescs, cbTxTemplate)
	if err != nil {
		log.Fatalf("error in CoinbaseTxGen")
	}
	fmt.Fprintln(f, "txoscript:")
	for i := 0; i < len(genesisCoinbaseTx.TxOuts[0].TxoScript); i++ {
		fmt.Fprintf(f, "%#02X, ", genesisCoinbaseTx.TxOuts[0].TxoScript[i])
		if i%16 == 15 {
			fmt.Fprintln(f)
		}
	}
	fmt.Fprintln(f)
	fmt.Fprintln(f, "txwitness:")
	for i := 0; i < len(genesisCoinbaseTx.TxWitness); i++ {
		fmt.Fprintf(f, "%#02X, ", genesisCoinbaseTx.TxWitness[i])
		if i%16 == 15 {
			fmt.Fprintln(f)
		}
	}
	fmt.Fprintln(f)
	blockTxns := make([]*abeutil.TxAbe, 1)
	coinbaseTx := abeutil.NewTxAbe(genesisCoinbaseTx)
	blockTxns[0] = coinbaseTx
	genesisMerkleRoot := blockchain.BuildMerkleTreeStoreAbe(blockTxns, false)

	fmt.Fprintln(f, "coinbase tx hash:")
	for i := 0; i < len(genesisMerkleRoot[len(genesisMerkleRoot)-1]); i++ {
		fmt.Fprintf(f, "%#2x, ", genesisMerkleRoot[len(genesisMerkleRoot)-1][i])
	}
	fmt.Fprintln(f)
	currentTime := time.Now()
	fmt.Fprintln(f, "Time:")
	fmt.Fprintf(f, "%#x\n", currentTime.Unix())
	fmt.Fprintln(f)
	genesisWitnessHash := chainhash.DoubleHashH(genesisCoinbaseTx.TxWitness)
	fmt.Fprintln(f, "coinbase witness hash")
	for i := 0; i < len(genesisWitnessHash); i++ {
		fmt.Fprintf(f, "%#2x, ", genesisWitnessHash[i])
	}
	fmt.Fprintln(f)
	genesisBlock := wire.MsgBlockAbe{
		Header: wire.BlockHeader{
			Version:    0x10000000,
			PrevBlock:  chainhash.ZeroHash,
			MerkleRoot: *genesisMerkleRoot[len(genesisMerkleRoot)-1],
			Timestamp:  currentTime,
			Bits:       0x1e01ad7f,
			Nonce:      0,
		},
		Transactions: []*wire.MsgTxAbe{genesisCoinbaseTx},
		WitnessHashs: []*chainhash.Hash{&genesisWitnessHash},
	}
	now := time.Now()
	for i := uint32(0); i <= ^uint32(0); i++ {
		genesisBlock.Header.Nonce = i
		if i%10000000 == 0 {
			fmt.Fprintf(f, "current i = %d\n", i)
		}
		hash := genesisBlock.Header.BlockHash()
		targetDifficulty := blockchain.CompactToBig(genesisBlock.Header.Bits)
		if blockchain.HashToBig(&hash).Cmp(targetDifficulty) <= 0 {
			fmt.Fprintln(f, "Successful!")
			fmt.Fprintln(f, "genesis block hash:")
			for i := 0; i < len(hash); i++ {
				fmt.Fprintf(f, "%#.2x, ", hash[i])
			}
			fmt.Fprintln(f)
			fmt.Fprintln(f, "Nonce:")
			fmt.Fprintf(f, "%#x\n", genesisBlock.Header.Nonce)
			fmt.Fprintln(f, time.Since(now))
			return
		}
	}
	return
}
