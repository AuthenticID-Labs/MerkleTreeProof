import { MerkleTree } from 'merkletreejs';
import { ethers, providers, Signer, utils } from 'ethers';
import * as MyRegistrar from './contracts/MyRegistrar.json';
import * as crypto from 'crypto';

function sha256(data: string) {
  return crypto.createHash('sha256').update(data).digest()
}

const CONTRACT_ADDRESS = '0x5b7D656f9D21d9FC727d8C52eb939661aF28D680';
export const generateMerkleTreeRoot = (input: string[]) => {
  const tree = generateMerkleTree(input);
  const root = `0x${tree.getRoot().toString('hex')}`;

  return root;
}

export const generateMerkleTree = (input: string[]) => {
  const sortedInput = input.sort();
  const leaves = sortedInput.map(entry => sha256(entry));
  const tree = new MerkleTree(leaves, sha256);
  
  return tree;
}

export const doMerkleVerify = (tree: MerkleTree, toTest: string, root: string) => {
  const leaf = sha256(toTest);
  const proof = tree.getProof(leaf);
  const result = tree.verify(proof, leaf, root);
  
  return result;
}

export const getMerkleProof = (tree: MerkleTree, leaf: string) => {
  const _leaf = sha256(leaf);
  return tree.getHexProof(_leaf);
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