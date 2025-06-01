// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {EmailDomainProver} from "./EmailDomainProver.sol";

import {Proof} from "vlayer-0.1.0/Proof.sol";
import {Verifier} from "vlayer-0.1.0/Verifier.sol";
import {ERC721} from "@openzeppelin-contracts-5.0.1/token/ERC721/ERC721.sol";

contract EmailDomainVerifier is Verifier {
    address public prover;

    mapping(string => bool) public takenHashes;

    constructor(address _prover) {
        prover = _prover;
    }

    function verify(Proof memory, string memory, string memory hash)
        public
        onlyVerified(prover, EmailDomainProver.main.selector)
    {
        require(takenHashes[hash] == false, "hash taken");

        takenHashes[hash] = true;
    }
}
