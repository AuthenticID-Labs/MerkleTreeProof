import { generateMerkleTreeRoot, generateMerkleTree, doMerkleVerify, getMerkleProof } from '../index';
import * as crypto from 'crypto';
import MerkleTree from 'merkletreejs';

function sha256(data: string) {
  return crypto.createHash('sha256').update(data).digest()
}



test('Create User Two', () => {
  const leaves = [
    "CountryCode:MEX",
    "EyeColor:GREEN",
    "HairColor:PINK",
    "Sex:MALE",
  ];

  const tree = generateMerkleTree(leaves);
  
  const proof = tree.getProof(sha256(leaves[1]));
  console.log('leaves: ', tree.getHexLeaves());
  console.log('hex root: ', tree.getHexRoot());
  console.log('eye proof: ', proof);
  console.log('eye proof: ',tree.getHexProof(sha256(leaves[1])));
  console.log('hair proof: ',tree.getHexProof(sha256(leaves[2])));
  console.log(getMerkleProof(tree, 'EyeColor:GREEN'));
  const stringifiedProof = JSON.stringify(proof);
  console.log(stringifiedProof);
  const parsedProof = JSON.parse(stringifiedProof)
  const xx = parsedProof.map((e: any) => {
    const {position, data} = e;
    return {position, data: Buffer.from(data)}
  });
  console.log('Parsed Proof: ', xx);
  expect(
    MerkleTree.verify(
    xx, 
    '0x26dbfb5fecd1573e9589cb038879449263b31e665feb754a44c2449903c37377',
    '0x2641fecfae2f5bb12ee34a92211be38a0b94c2ecd52f15bd1322363bf61e008d',
    sha256)
  ).toBe(true);
})

test('Exists in tree', () => {
  const root = generateMerkleTreeRoot(['harry', 'liam', 'bruce', 'bob', 'shawn']);

  const tree = generateMerkleTree(['bob', 'harry', 'shawn', 'liam', 'bruce']);

  expect(doMerkleVerify(tree, 'shawn', root)).toBe(true);
})

test('Not in tree', () => {
  const root = generateMerkleTreeRoot(['harry', 'liam', 'bruce', 'bob', 'shawn']);

  const tree = generateMerkleTree(['bob', 'harry', 'shawn', 'liam', 'bruce']);

  expect(doMerkleVerify(tree, 'steve', root)).toBe(false);
})

test('Wrong tree', () => {
  const root = generateMerkleTreeRoot(['harry', 'liam', 'bruce', 'bob', 'shawn']);

  const tree = generateMerkleTree(['dave', 'harry', 'shawn', 'liam', 'bruce']);

  expect(doMerkleVerify(tree, 'shawn', root)).toBe(false);
})



/*
'0x00000000000000000000000000000000000000000064617665202d3e20626f62',
'0xc75a93e62fa0f43bbeaf8f0d7d68d3114012537a2b3a8fc745a48a3563a62d69'

0xc0bd4e2e3e0f2f979c02529ed0a988bc339b51946ad97e22543777e2a6025940
0xc0bd4e2e3e0f2f979c02529ed0a988bc339b51946ad97e22543777e2a6025940


    hex root:  0x510a7ba2acbdfa3e4efdae611e3cbc6dbd6c3c4289c9ae33c56f4de193701a41
[
      '0x30e0bebaa6ff371e0f9846ffe43f5ea2b69496ddd62c50ed02ac4f2e0a840709',
      '0x590e9e4a912fb1984227f09b1d812c93b301adc163cb575154f7d52cfe8bb53b',
      '0xe5d5c95b7fc4252f852a08511b1c2ded57690052769a15744f1121f8aacd1f6a',
      '0x992ec4ab2418cd49f70ace407d1520a00a1893804bcc1340fad1944151c32c9b'
    ]

["0x30e0bebaa6ff371e0f9846ffe43f5ea2b69496ddd62c50ed02ac4f2e0a840709","0x0590d1f788073880659e87bae02ba7085117a77f65957c2684553115acebcb62"]

["0x992ec4ab2418cd49f70ace407d1520a00a1893804bcc1340fad1944151c32c9b","0x1615dc58a1f7aff562edfec598228989ce075ee5ac928a2583ba04381d30a4e0"]




[
      '0x30e0bebaa6ff371e0f9846ffe43f5ea2b69496ddd62c50ed02ac4f2e0a840709',
      '0x67cb5406ee2b35ae6a7403fd8101a4a6c2a268f7576c1d81ad2f8c33b8a97657',
      '0xce308852879c333772c97fed60dac3115e4b3dda5317d737c7258f8827ded7db',
      '0xd79536498014d2975ae7c50cd6270be05740def6fb4a0e977de374c97183ed82'
    ]

      at Object.<anonymous> (src/__tests__/index.test.ts:20:11)

  console.log
    hex root:  0xa2e19dc35995d685f70c0131fa843de2fda010db7c61c1d8fe37153760a83452

      at Object.<anonymous> (src/__tests__/index.test.ts:21:11)

  console.log
["0x30e0bebaa6ff371e0f9846ffe43f5ea2b69496ddd62c50ed02ac4f2e0a840709","0xbd18f36b0ebf4c356e825689da88816510f129dfce691f315bf4b50206498056"]

      at Object.<anonymous> (src/__tests__/index.test.ts:22:11)

  console.log
["0xd79536498014d2975ae7c50cd6270be05740def6fb4a0e977de374c97183ed82',"0x1d050dc9468cf66e48fbb26cf3e65f14ea4874d92c97d721bb1aea802798a773"]
*/