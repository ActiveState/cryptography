# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
from cryptography.hazmat.primitives.asymmetric import ec

EC_KEY_SECT571R1 = ec.EllipticCurvePrivateNumbers(private_value=int('2139970696971086346218682513350761791903832720875488889687886989531319283754315701227531300549662690382440760498694767365478965492017388482714521707824160638375437887802901'), public_numbers=ec.EllipticCurvePublicNumbers(curve=ec.SECT571R1(), x=int('4258567241090052089528701943226751415643268668129016423026227854789182447139054594501570747809649335533486119017169439209005883737780433424425566023654583165324498640038089'), y=int('138225233202093875725004581047998068516580245374772282507383344697785151477753129657276384825327903473355077492772043649432197281333379623823457479233585424800362717541750')))
EC_KEY_SECT409R1 = ec.EllipticCurvePrivateNumbers(private_value=int('604993237916498765317587097853603474519114726157206838874832379003281871982139714656205843929472002062791572217653118715727'), public_numbers=ec.EllipticCurvePublicNumbers(curve=ec.SECT409R1(), x=int('762377013392689280390872388700736798146466640107835443015892692272579213400205907766385199643053767195204247826349822350081'), y=int('1005666892961838304520486606011062656339234549492530247835174401475129090774493235522729123877384838835703483224447476728811')))
EC_KEY_SECT283R1 = ec.EllipticCurvePrivateNumbers(private_value=int('5897050772556584349621187898014025734955472072399170432412737536710603230261342427657'), public_numbers=ec.EllipticCurvePublicNumbers(curve=ec.SECT283R1(), x=int('10694213430317013187241490088760888472172922291550831393222973531614941756901942108493'), y=int('114615531003139435153736013675273996495933667282629182149421164359557613202950705170')))
EC_KEY_SECT233R1 = ec.EllipticCurvePrivateNumbers(private_value=int('3434700671053881447571352612326587421428301547537396480951018998298288'), public_numbers=ec.EllipticCurvePublicNumbers(curve=ec.SECT233R1(), x=int('7449495156915155769219507146512814064614076518869829406255037471118267'), y=int('4869915082302296250854492382587616448591700116246140179751174844872205')))
EC_KEY_SECT163R2 = ec.EllipticCurvePrivateNumbers(private_value=int('11788436193853888218177032687141056784083668635'), public_numbers=ec.EllipticCurvePublicNumbers(curve=ec.SECT163R2(), x=int('5247234453330640212490501030772203801908103222463'), y=int('3172513801099088785224248292142866317754124455206')))
EC_KEY_SECT571K1 = ec.EllipticCurvePrivateNumbers(private_value=int('592811051234886966121888758661314648311634839499582476726008738218165015048237934517672316204181933804884636855291118594744334592153883208936227914544246799490897169723387'), public_numbers=ec.EllipticCurvePublicNumbers(curve=ec.SECT571K1(), x=int('813624714619365522038984558741829169398577748726436078842500522930133652410523072965388178937341299092149355125348186631718150644729351721577822595637058949405764944491655'), y=int('1405804126081294539606782106106361804789681471982863724166126031235681542401975593036630733881695595289523801041910183736211587294494888450327374439795428519848065589000434')))
EC_KEY_SECT409K1 = ec.EllipticCurvePrivateNumbers(private_value=int('110321743150399087059465162400463719641470113494908091197354523708934106732952992153105338671368548199643686444619485307877'), public_numbers=ec.EllipticCurvePublicNumbers(curve=ec.SECT409K1(), x=int('622802142094103634935251787979449957421196001459537559164261610790364158569265348038207313261547476506319796469776797725796'), y=int('466538837491024742890950101087775799074224728045771853693320187318642669590280811057512951467298158275464566214288556375885')))
EC_KEY_SECT283K1 = ec.EllipticCurvePrivateNumbers(private_value=int('1825083944154440141565747331415493315381282343953564661083100151303868915489347291850'), public_numbers=ec.EllipticCurvePublicNumbers(curve=ec.SECT283K1(), x=int('311416472061118864263507031236704515541231809103795927647738852959123367428352287032'), y=int('7178746014448366596458518783728396308996476070406520537617538458957627834444017112582')))
EC_KEY_SECT233K1 = ec.EllipticCurvePrivateNumbers(private_value=int('1726700896474746137340914360819605508012547759026298918923944710862070'), public_numbers=ec.EllipticCurvePublicNumbers(curve=ec.SECT233K1(), x=int('5569391147433951099152157939220288956137367897392942635473704868129172'), y=int('11025856248546376145959939911850923631416718241836051344384802737277815')))
EC_KEY_SECT163K1 = ec.EllipticCurvePrivateNumbers(private_value=int('3699303791425402204035307605170569820290317991287'), public_numbers=ec.EllipticCurvePublicNumbers(curve=ec.SECT163K1(), x=int('4479755902310063321544063130576409926980094120721'), y=int('3051218481937171839039826690648109285113977745779')))
EC_KEY_SECP521R1 = ec.EllipticCurvePrivateNumbers(private_value=int('6627512352154608862902939026581288474953476911992147066970891407696722739507679613314422655305240639435488467243480486142397914984425997823106818915698960565'), public_numbers=ec.EllipticCurvePublicNumbers(curve=ec.SECP521R1(), x=int('1294474282625742084665952775268376319340138427139151328602291729910013082920512632908350502247952686156279140016049549948975670668730618745449113644014505462'), y=int('1078410881027197618673758774943629578298556364036868908105288616296815984553198866894145509329328086635278430266482551941240591605833440825557820439734509311')))
EC_KEY_SECP384R1 = ec.EllipticCurvePrivateNumbers(private_value=int('28081410713485847059875391639480752139823963353428163398257609908335787109896602102090002196616273211495718603965098'), public_numbers=ec.EllipticCurvePublicNumbers(curve=ec.SECP384R1(), x=int('10036914308591746758780165503819213553101287571902957054148542504671046744460374996612408381962208627004841444205030'), y=int('17337335659928075994560513699823544906448896792102247714689323575406618073069185107088229463828921069465902299522926')))
EC_KEY_SECP256R1 = ec.EllipticCurvePrivateNumbers(private_value=int('27103297851159561764984416831623434465692121869941446124050263501025776962849'), public_numbers=ec.EllipticCurvePublicNumbers(curve=ec.SECP256R1(), x=int('49325986169170464532722748935508337546545346352733747948730305442770101441241'), y=int('51709162888529903487188595007092772817469799707382623884187518455962250433661')))
EC_KEY_SECP256K1 = ec.EllipticCurvePrivateNumbers(private_value=int('68334156900847359376587922277420767745881036297632753056321531804864380736732'), public_numbers=ec.EllipticCurvePublicNumbers(curve=ec.SECP256K1(), x=int('59251322975795306609293064274738085741081547489119277536110995120127593127884'), y=int('103341920014803920392278018322013401476059407178412946441870718261641142297801')))
EC_KEY_SECP224R1 = ec.EllipticCurvePrivateNumbers(private_value=int('23485434049277434264250551908241323328238306688075690083404756625150'), public_numbers=ec.EllipticCurvePublicNumbers(curve=ec.SECP224R1(), x=int('511656766382712046910950813415816214879984226452615738242396661214'), y=int('149366014505557113091583971727199638438919262091685334537179691265')))
EC_KEY_SECP192R1 = ec.EllipticCurvePrivateNumbers(private_value=int('4534766128536179420071447168915990251715442361606049349869'), public_numbers=ec.EllipticCurvePublicNumbers(curve=ec.SECP192R1(), x=int('5415069751170397888083674339683360671310515485781457536999'), y=int('18671605334415960797751252911958331304288357195986572776')))