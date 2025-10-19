// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract BioZeroRegistry {
    struct Commitment {
        bytes32 commitmentHash;
        bytes32 nonceHash;
        uint256 registeredAt;
        bool registered;
    }

    struct VerificationRecord {
        bool accepted;
        uint256 distance;
        uint256 threshold;
        bytes32 transcriptDigest;
        uint256 timestamp;
    }

    mapping(bytes32 => Commitment) private commitments;
    mapping(bytes32 => VerificationRecord) private verifications;

    event Registered(bytes32 indexed userIdHash, bytes32 commitmentHash, bytes32 nonceHash);
    event VerificationStored(bytes32 indexed userIdHash, bool accepted, uint256 distance, uint256 threshold, bytes32 transcriptDigest);

    error AlreadyRegistered(bytes32 userIdHash);
    error NotRegistered(bytes32 userIdHash);
    error InvalidParameters();

    function register(bytes32 userIdHash, bytes32 commitmentHash, bytes32 nonceHash) external {
        if (userIdHash == bytes32(0) || commitmentHash == bytes32(0) || nonceHash == bytes32(0)) {
            revert InvalidParameters();
        }

        Commitment storage record = commitments[userIdHash];
        if (record.registered) {
            revert AlreadyRegistered(userIdHash);
        }

        record.commitmentHash = commitmentHash;
        record.nonceHash = nonceHash;
        record.registeredAt = block.timestamp;
        record.registered = true;

        emit Registered(userIdHash, commitmentHash, nonceHash);
    }

    function authenticate(
        bytes32 userIdHash,
        uint256 distance,
        uint256 threshold,
        bytes32 transcriptDigest
    ) external {
        Commitment storage record = commitments[userIdHash];
        if (!record.registered) {
            revert NotRegistered(userIdHash);
        }

        if (threshold == 0 || transcriptDigest == bytes32(0)) {
            revert InvalidParameters();
        }

        bool accepted = distance <= threshold;

        verifications[userIdHash] = VerificationRecord({
            accepted: accepted,
            distance: distance,
            threshold: threshold,
            transcriptDigest: transcriptDigest,
            timestamp: block.timestamp
        });

        emit VerificationStored(userIdHash, accepted, distance, threshold, transcriptDigest);
    }

    function getCommitment(bytes32 userIdHash) external view returns (Commitment memory) {
        return commitments[userIdHash];
    }

    function getVerification(bytes32 userIdHash) external view returns (VerificationRecord memory) {
        return verifications[userIdHash];
    }
}
