
```
npm i @authenticid-labs/merkle-tree-proof
```
or
```
yarn add @authenticid-labs/merkle-tree-proof
```

#### Usage

```
const { generateMerkleTreeRoot, generateMerkleTree, doMerkleProof, getMerkleTreeRoot } = require('@authenticid-labs/merkle-tree-proof');

const root = await getMerkleTreeRoot(provider, wallet_address);
const tree = generateMerkleTree(input: string[]);
const success = doMerkleProof(tree: MerkleTree, toTest: string, root: string);

```
