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


[
  {
    "index":14,
    "key":"HairColor",
    "value":"BROWN",
    "proof":[{"position":"right","data":{"type":"Buffer","data":[101,127,227,225,28,169,83,65,76,203,114,97,233,136,231,114,106,240,222,46,147,173,79,76,188,53,26,227,23,217,2,172]}},{"position":"left","data":{"type":"Buffer","data":[170,205,203,129,57,165,253,243,39,3,38,181,152,168,101,178,0,20,18,81,246,210,90,110,153,164,194,77,44,168,140,220]}},{"position":"left","data":{"type":"Buffer","data":[248,114,27,253,150,52,176,0,87,160,60,15,208,133,119,161,60,74,22,249,132,208,16,147,93,84,62,25,241,92,6,29]}},{"position":"left","data":{"type":"Buffer","data":[116,210,203,72,16,124,55,234,16,45,240,129,159,78,151,82,126,50,76,147,241,105,244,134,242,74,80,143,31,219,205,205]}},{"position":"right","data":{"type":"Buffer","data":[12,224,7,96,48,212,175,16,132,31,68,150,183,144,113,143,167,74,46,222,215,179,34,30,63,80,138,132,79,224,117,22]}}]},{"index":11,"key":"EyeColor","value":"BROWN","proof":[{"position":"left","data":{"type":"Buffer","data":[155,93,112,14,23,221,164,50,154,116,191,242,165,69,221,218,80,123,113,252,28,156,37,59,15,251,40,89,123,211,174,221]}},{"position":"left","data":{"type":"Buffer","data":[198,107,126,205,226,99,148,105,181,211,246,162,32,234,88,111,245,61,218,3,193,199,180,6,7,186,79,78,5,134,87,224]}},{"position":"right","data":{"type":"Buffer","data":[51,59,35,213,61,13,191,246,1,204,71,212,139,73,44,5,76,211,76,39,33,192,116,7,119,14,24,184,12,130,62,23]}},{"position":"left","data":{"type":"Buffer","data":[116,210,203,72,16,124,55,234,16,45,240,129,159,78,151,82,126,50,76,147,241,105,244,134,242,74,80,143,31,219,205,205]}},{"position":"right","data":{"type":"Buffer","data":[12,224,7,96,48,212,175,16,132,31,68,150,183,144,113,143,167,74,46,222,215,179,34,30,63,80,138,132,79,224,117,22]}}]}]

*/