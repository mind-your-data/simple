// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {Strings} from "@openzeppelin-contracts-5.0.1/utils/Strings.sol";
import {Proof} from "vlayer-0.1.0/Proof.sol";
import {Prover} from "vlayer-0.1.0/Prover.sol";
import {RegexLib} from "vlayer-0.1.0/Regex.sol";
import {VerifiedEmail, UnverifiedEmail, EmailProofLib} from "vlayer-0.1.0/EmailProof.sol";

contract EmailDomainProver is Prover {
    using RegexLib for string;
    using Strings for string;
    using EmailProofLib for UnverifiedEmail;

    function main(UnverifiedEmail calldata unverifiedEmail, string calldata script, string calldata secret)
        public
        view
        returns (Proof memory, string memory, string memory)
    {
        VerifiedEmail memory email = unverifiedEmail.verify();
        string[] memory subjectCapture = email.subject.capture("^Claim reward for running the computation on my private data");
        require(subjectCapture.length > 0, "no wallet address in subject");
        
        // Calculate script hash
        bytes32 scriptHash = sha256(bytes(script));
        
        // Convert scriptHash to hex string
        string memory hash = string.concat(Strings.toHexString(uint256(scriptHash)), secret);

        require(keccak256(bytes(hash)) == keccak256(bytes(email.body)), "invalid secret");

        return (proof(), script, hash);
    }
}
