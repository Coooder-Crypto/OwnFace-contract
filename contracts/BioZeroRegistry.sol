// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract BioZeroRegistry {
    address public recorder;

    struct Commitment {
        bytes32 commitmentHash;
        bytes commitmentPoint;
        bytes32 blinding;
        bytes32 nonceHash;
        uint256 registeredAt;
        bool registered;
    }

    struct VerificationRecord {
        bool accepted;
        uint256 distance;
        uint256 threshold;
        bytes32 transcriptDigest;
        bytes32 proofHash;
        uint256 timestamp;
    }

    mapping(bytes32 => Commitment) private commitments;
    mapping(bytes32 => VerificationRecord) private verifications;

    event Registered(
        bytes32 indexed userIdHash,
        bytes32 commitmentHash,
        bytes32 nonceHash,
        bytes commitmentPoint,
        bytes32 blinding
    );
    event VerificationStored(
        bytes32 indexed userIdHash,
        bool accepted,
        uint256 distance,
        uint256 threshold,
        bytes32 transcriptDigest,
        bytes32 proofHash
    );

    error AlreadyRegistered(bytes32 userIdHash);
    error NotRegistered(bytes32 userIdHash);
    error InvalidParameters();
    error NotAuthorised();

    modifier onlyRecorder() {
        if (msg.sender != recorder) {
            revert NotAuthorised();
        }
        _;
    }

    constructor(address recorder_) {
        recorder = recorder_;
    }

    function register(
        bytes32 userIdHash,
        bytes32 commitmentHash,
        bytes32 nonceHash,
        bytes calldata commitmentPoint,
        bytes32 blinding
    ) external onlyRecorder {
        if (userIdHash == bytes32(0) || commitmentHash == bytes32(0) || nonceHash == bytes32(0)) {
            revert InvalidParameters();
        }

        Commitment storage record = commitments[userIdHash];
        if (record.registered) {
            revert AlreadyRegistered(userIdHash);
        }

        record.commitmentHash = commitmentHash;
        record.commitmentPoint = commitmentPoint;
        record.blinding = blinding;
        record.nonceHash = nonceHash;
        record.registeredAt = block.timestamp;
        record.registered = true;

        emit Registered(userIdHash, commitmentHash, nonceHash, commitmentPoint, blinding);
    }

    function authenticate(
        bytes32 userIdHash,
        bool accepted,
        uint256 distance,
        uint256 threshold,
        bytes32 transcriptDigest,
        bytes32 proofHash
    ) external onlyRecorder {
        Commitment storage record = commitments[userIdHash];
        if (!record.registered) {
            revert NotRegistered(userIdHash);
        }

        if (threshold == 0 || transcriptDigest == bytes32(0)) {
            revert InvalidParameters();
        }

        verifications[userIdHash] = VerificationRecord({
            accepted: accepted,
            distance: distance,
            threshold: threshold,
            transcriptDigest: transcriptDigest,
            proofHash: proofHash,
            timestamp: block.timestamp
        });

        emit VerificationStored(userIdHash, accepted, distance, threshold, transcriptDigest, proofHash);
    }

    function getCommitment(bytes32 userIdHash) external view returns (Commitment memory) {
        return commitments[userIdHash];
    }

    function getVerification(bytes32 userIdHash) external view returns (VerificationRecord memory) {
        return verifications[userIdHash];
    }
}
