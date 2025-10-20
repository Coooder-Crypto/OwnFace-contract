// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IGroth16Verifier {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[] memory input
    ) external view returns (bool);
}

contract OwnFaceRegistry {
    address public recorder;
    IGroth16Verifier public verifier;

    struct Commitment {
        bytes32 commitmentHash;
        bytes commitmentPoint;
        bytes32 blinding;
        bytes32 nonceHash;
        uint256 vectorHash;
        uint256 registeredAt;
        bool registered;
    }

    struct VerificationRecord {
        bool accepted;
        uint256 distance;
        uint256 threshold;
        uint256 referenceHash;
        uint256 candidateHash;
        uint256 transcriptHash;
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
        bytes32 blinding,
        uint256 vectorHash
    );
    event VerificationStored(
        bytes32 indexed userIdHash,
        bool accepted,
        uint256 distance,
        uint256 threshold,
        uint256 referenceHash,
        uint256 candidateHash,
        uint256 transcriptHash,
        bytes32 proofHash
    );

    error AlreadyRegistered(bytes32 userIdHash);
    error NotRegistered(bytes32 userIdHash);
    error InvalidParameters();
    error InvalidProof();
    error NotAuthorised();

    modifier onlyRecorder() {
        if (msg.sender != recorder) {
            revert NotAuthorised();
        }
        _;
    }

    constructor(address recorder_, address verifier_) {
        if (recorder_ == address(0) || verifier_ == address(0)) {
            revert InvalidParameters();
        }
        recorder = recorder_;
        verifier = IGroth16Verifier(verifier_);
    }

    function register(
        bytes32 userIdHash,
        bytes32 commitmentHash,
        bytes32 nonceHash,
        bytes calldata commitmentPoint,
        bytes32 blinding,
        uint256 vectorHash
    ) external onlyRecorder {
        if (
            userIdHash == bytes32(0) ||
            commitmentHash == bytes32(0) ||
            nonceHash == bytes32(0) ||
            vectorHash == 0
        ) {
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
        record.vectorHash = vectorHash;
        record.registeredAt = block.timestamp;
        record.registered = true;

        emit Registered(userIdHash, commitmentHash, nonceHash, commitmentPoint, blinding, vectorHash);
    }

    function authenticate(
        bytes32 userIdHash,
        bytes32 proofHash,
        uint256[2] calldata proofA,
        uint256[2][2] calldata proofB,
        uint256[2] calldata proofC,
        uint256[6] calldata publicSignals
    ) external onlyRecorder {
        Commitment storage record = commitments[userIdHash];
        if (!record.registered) {
            revert NotRegistered(userIdHash);
        }

        uint256 distance = publicSignals[0];
        uint256 threshold = publicSignals[1];
        uint256 within = publicSignals[2];
        uint256 referenceHash = publicSignals[3];
        uint256 candidateHash = publicSignals[4];
        uint256 transcriptHash = publicSignals[5];

        if (threshold == 0 || within > 1 || referenceHash == 0 || transcriptHash == 0) {
            revert InvalidParameters();
        }

        if (referenceHash != record.vectorHash) {
            revert InvalidProof();
        }

        uint256[] memory input = new uint256[](6);
        for (uint256 i = 0; i < 6; i++) {
            input[i] = publicSignals[i];
        }

        bool verified = verifier.verifyProof(proofA, proofB, proofC, input);
        if (!verified) {
            revert InvalidProof();
        }

        bool accepted = within == 1;

        verifications[userIdHash] = VerificationRecord({
            accepted: accepted,
            distance: distance,
            threshold: threshold,
            referenceHash: referenceHash,
            candidateHash: candidateHash,
            transcriptHash: transcriptHash,
            proofHash: proofHash,
            timestamp: block.timestamp
        });

        emit VerificationStored(
            userIdHash,
            accepted,
            distance,
            threshold,
            referenceHash,
            candidateHash,
            transcriptHash,
            proofHash
        );
    }

    function getCommitment(bytes32 userIdHash) external view returns (Commitment memory) {
        return commitments[userIdHash];
    }

    function getVerification(bytes32 userIdHash) external view returns (VerificationRecord memory) {
        return verifications[userIdHash];
    }
}
