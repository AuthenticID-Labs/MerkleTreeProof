import { MerkleTree } from 'merkletreejs';
import { ethers, providers, Signer, utils } from 'ethers';
import * as MyRegistrar from './contracts/MyRegistrar.json';
import * as crypto from 'crypto';

function sha256(data: string) {
  return crypto.createHash('sha256').update(data).digest()
}

const CONTRACT_ADDRESS = '0xA0C7Aaf36175B62663a4319EB309Da47A19ec518';
export const generateMerkleTreeRoot = (input: string[]) => {
  const tree = generateMerkleTree(input);
  const root = `0x${tree.getRoot().toString('hex')}`;
  console.log('root: ', root);

  return root;
}

export const generateMerkleTree = (input: string[]) => {
  const sortedInput = input.sort();
  const leaves = sortedInput.map(entry => sha256(entry));
  const tree = new MerkleTree(leaves, sha256);
  console.log('tree: ', tree);
  
  return tree;
}

export const doMerkleProof = (tree: MerkleTree, toTest: string, root: string) => {
  const leaf = sha256(toTest);
  const proof = tree.getProof(leaf);
  const result = tree.verify(proof, leaf, root);
  
  return result;
}

export const getMerkleTreeRoot = async (provider: providers.Provider | Signer, address: string): Promise<string> => {
  try {
    const contract = new ethers.Contract(CONTRACT_ADDRESS, MyRegistrar.abi, provider);
    const root = await contract.getHash(address);

    return root;
  } catch (error) {
    throw error;
  }
};