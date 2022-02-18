import { generateMerkleTreeRoot, generateMerkleTree, doMerkleProof } from '../index';
import { ethers, providers, Signer } from 'ethers';

test('Exists in tree', () => {
  const root = generateMerkleTreeRoot(['harry', 'liam', 'bruce', 'bob', 'shawn']);

  const tree = generateMerkleTree(['bob', 'harry', 'shawn', 'liam', 'bruce']);

  expect(doMerkleProof(tree, 'shawn', root)).toBe(true);
})

test('Not in tree', () => {
  const root = generateMerkleTreeRoot(['harry', 'liam', 'bruce', 'bob', 'shawn']);

  const tree = generateMerkleTree(['bob', 'harry', 'shawn', 'liam', 'bruce']);

  expect(doMerkleProof(tree, 'steve', root)).toBe(false);
})

test('Wrong tree', () => {
  const root = generateMerkleTreeRoot(['harry', 'liam', 'bruce', 'bob', 'shawn']);

  const tree = generateMerkleTree(['dave', 'harry', 'shawn', 'liam', 'bruce']);

  expect(doMerkleProof(tree, 'shawn', root)).toBe(false);
})

