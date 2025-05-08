// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/Base64.sol";

/**
 * @title AgentCoordination
 * @dev A contract for enabling AI agents to coordinate through on-chain memory and metadata
 * with support for API access delegation. Modified to remove centralized access control,
 * enhance proxy approach, and secure token usage.
 */
contract AgentCoordination is ERC721, Ownable {
    using Counters for Counters.Counter;
    using Strings for uint256;

    Counters.Counter private _agentIdCounter;
    Counters.Counter private _intentIdCounter;
    Counters.Counter private _actionIdCounter;
    Counters.Counter private _accessTokenIdCounter;

    // Custom errors for better error handling
    error NotAgentOwner(string agentId, address caller);
    error InvalidTokenUsage(bytes32 tokenId);
    error ActionDoesNotExist(uint256 actionId);
    error RewardTransferFailed(address recipient, uint256 amount);
    error AgentDoesNotExist(string agentId);
    error AgentNotActive(string agentId);
    error IntentDoesNotExist(uint256 intentId);
    error IntentAlreadyFulfilled(uint256 intentId);
    error IntentExpired(uint256 intentId);
    error TokenDoesNotExist(bytes32 tokenId);
    error TokenRevoked(bytes32 tokenId);
    error TokenExpired(bytes32 tokenId);
    error TokenUsageLimitReached(bytes32 tokenId);
    error NotTargetAgent(bytes32 tokenId, address caller);
    error InvalidProxyAction(bytes32 accessTokenId);

    // Struct for agent metadata
    struct Agent {
        string agentId;             // Unique identifier for the agent
        string name;                // Human-readable name
        string description;         // Description of the agent's purpose
        string[] capabilities;      // List of capabilities this agent has
        string[] roles;             // Roles this agent can fulfill
        string ipfsMetadata;        // Extended metadata stored on IPFS (optional)
        string apiEndpoint;         // Main API endpoint (optional)
        address owner;              // Address that registered this agent
        uint256 timestamp;          // When the agent was registered
        bool active;                // Whether the agent is currently active
    }

    // Struct for capability-specific endpoints
    struct CapabilityEndpoint {
        string capability;          // Capability name
        string endpoint;            // Endpoint URL for this capability
        string accessInstructions;  // Instructions for accessing this capability
    }

    // Struct for intent metadata
    struct Intent {
        uint256 id;                 // Unique identifier for this intent
        string agentId;             // ID of the agent that published the intent
        string intentType;          // Type of intent (e.g., "process-with-gpt4o")
        string description;         // Human-readable description
        string data;                // Intent data or parameters (JSON string)
        string[] requiredCapabilities; // Capabilities required to fulfill this intent
        uint256 reward;             // Optional reward for fulfilling (in wei)
        uint256 expiry;             // When this intent expires (0 = never)
        uint256 timestamp;          // When the intent was published
        bool fulfilled;             // Whether the intent has been fulfilled
        address payable publisher;  // Address that published the intent
    }

    // Struct for action metadata
    struct Action {
        uint256 id;                 // Unique identifier for this action
        uint256 intentId;           // ID of the intent being responded to
        string agentId;             // ID of the agent taking the action
        string actionType;          // Type of action being performed
        string data;                // Action data or result (JSON string)
        string evidence;            // Proof of work or result
        bytes32 evidenceHash;       // Hash of the evidence for proxy actions
        bytes32 accessTokenId;      // ID of access token (if any)
        bool proxyMode;             // Whether this is a proxy action
        bool requiresCallback;      // Whether this action needs a callback
        uint256 timestamp;          // When the action was performed
        bool accepted;              // Whether the action was accepted by the intent publisher
        address actor;              // Address that performed the action
    }

    // Struct for API access tokens
    struct AccessToken {
        bytes32 id;                 // Unique identifier for this token
        string issuerAgentId;       // Agent that created the token
        string targetAgentId;       // Agent that can use the token
        string capability;          // What capability this grants access to
        string accessData;          // Encrypted/hashed access data (JSON string)
        // Note: accessData should contain encrypted credentials; off-chain communication must use secure channels (e.g., TLS)
        uint256 expiresAt;          // When the token expires
        uint256 usageLimit;         // How many times it can be used
        uint256 usageCount;         // How many times it has been used
        bool revoked;               // Whether the token is revoked
        uint256 timestamp;          // When the token was created
    }

    // Storage for agents, intents, actions, and tokens
    mapping(string => Agent) public agents;
    mapping(uint256 => Intent) public intents;
    mapping(uint256 => Action) public actions;
    mapping(bytes32 => AccessToken) public accessTokens;

    // Track active agents (replaces registeredAgentIds for scalability)
    mapping(string => bool) public activeAgents;
    string[] public registeredAgentIds; // Kept for backward compatibility, but prefer activeAgents

    // Mapping from agent ID to capability endpoints
    mapping(string => CapabilityEndpoint[]) public agentCapabilityEndpoints;

    // Mapping from agent ID to intents published
    mapping(string => uint256[]) public agentIntents;

    // Mapping from agent ID to actions performed
    mapping(string => uint256[]) public agentActions;

    // Mapping from intent type to intent IDs
    mapping(string => uint256[]) public intentTypeIndex;

    // Mapping from required capability to intent IDs
    mapping(string => uint256[]) public capabilityIntentIndex;

    // Mapping from agent ID to their subscribed intent types
    mapping(string => string[]) public agentSubscriptions;

    // Mapping from (subscriber agent ID, intent type) to boolean
    mapping(bytes32 => bool) public hasSubscription;

    // Mapping from agent ID to tokens issued
    mapping(string => bytes32[]) public agentIssuedTokens;

    // Mapping from agent ID to tokens received
    mapping(string => bytes32[]) public agentReceivedTokens;

    // Events
    event AgentRegistered(string indexed agentId, string name, address owner);
    event AgentUpdated(string indexed agentId, string name);
    event IntentPublished(uint256 indexed intentId, string agentId, string intentType);
    event ActionPerformed(uint256 indexed actionId, uint256 intentId, string agentId);
    event ProxyActionPerformed(uint256 indexed actionId, uint256 intentId, string agentId, bytes32 evidenceHash);
    event ActionAccepted(uint256 indexed actionId, uint256 intentId);
    event SubscriptionAdded(string agentId, string intentType);
    event SubscriptionRemoved(string agentId, string intentType);
    event AccessTokenCreated(bytes32 indexed tokenId, string issuerAgentId, string targetAgentId, string capability);
    event AccessTokenRevoked(bytes32 indexed tokenId);
    event AccessTokenUsed(bytes32 indexed tokenId, uint256 usageCount);
    event CapabilityEndpointAdded(string agentId, string capability, string endpoint);

    /**
     * @dev Constructor sets the name and symbol of the NFT collection
     */
    constructor() ERC721("AgentCoordination", "AITC") {}

    /**
     * @dev Modifier to restrict function calls to the agent owner
     */
    modifier onlyAgentOwner(string memory agentId) {
        if (bytes(agents[agentId].agentId).length == 0) revert AgentDoesNotExist(agentId);
        if (agents[agentId].owner != msg.sender) revert NotAgentOwner(agentId, msg.sender);
        _;
    }

    /**
     * @dev Register a new agent
     */
    function registerAgent(
        string memory agentId,
        string memory name,
        string memory description,
        string[] memory capabilities,
        string[] memory roles,
        string memory ipfsMetadata,
        string memory apiEndpoint
    ) public returns (bool) {
        if (bytes(agentId).length == 0) revert("Agent ID cannot be empty");
        if (bytes(name).length == 0) revert("Name cannot be empty");
        if (bytes(agents[agentId].agentId).length != 0) revert("Agent ID already exists");

        agents[agentId] = Agent(
            agentId,
            name,
            description,
            capabilities,
            roles,
            ipfsMetadata,
            apiEndpoint,
            msg.sender,
            block.timestamp,
            true
        );

        activeAgents[agentId] = true;
        registeredAgentIds.push(agentId); // Kept for compatibility

        emit AgentRegistered(agentId, name, msg.sender);
        return true;
    }

    /**
     * @dev Update an existing agent
     */
    function updateAgent(
        string memory agentId,
        string memory name,
        string memory description,
        string[] memory capabilities,
        string[] memory roles,
        string memory ipfsMetadata,
        string memory apiEndpoint,
        bool active
    ) public onlyAgentOwner(agentId) returns (bool) {
        if (bytes(agentId).length == 0) revert("Agent ID cannot be empty");
        if (bytes(name).length == 0) revert("Name cannot be empty");

        Agent storage agent = agents[agentId];
        agent.name = name;
        agent.description = description;
        agent.capabilities = capabilities;
        agent.roles = roles;
        agent.ipfsMetadata = ipfsMetadata;
        agent.apiEndpoint = apiEndpoint;
        agent.active = active;
        activeAgents[agentId] = active;

        emit AgentUpdated(agentId, name);
        return true;
    }

    /**
     * @dev Add a capability-specific endpoint for an agent
     */
    function addCapabilityEndpoint(
        string memory agentId,
        string memory capability,
        string memory endpoint,
        string memory accessInstructions
    ) public onlyAgentOwner(agentId) returns (bool) {
        if (bytes(agentId).length == 0) revert("Agent ID cannot be empty");
        if (bytes(capability).length == 0) revert("Capability cannot be empty");
        if (bytes(endpoint).length == 0) revert("Endpoint cannot be empty");

        bool hasCapability = false;
        for (uint i = 0; i < agents[agentId].capabilities.length; i++) {
            if (keccak256(bytes(agents[agentId].capabilities[i])) == keccak256(bytes(capability))) {
                hasCapability = true;
                break;
            }
        }
        if (!hasCapability) revert("Agent does not have this capability");

        agentCapabilityEndpoints[agentId].push(CapabilityEndpoint(
            capability,
            endpoint,
            accessInstructions
        ));

        emit CapabilityEndpointAdded(agentId, capability, endpoint);
        return true;
    }

    /**
     * @dev Get capability endpoints for an agent
     */
    function getCapabilityEndpoints(string memory agentId) public view returns (CapabilityEndpoint[] memory) {
        return agentCapabilityEndpoints[agentId];
    }

    /**
     * @dev Get capability endpoint for a specific capability
     */
    function getCapabilityEndpoint(string memory agentId, string memory capability) 
        public view returns (string memory, string memory) 
    {
        CapabilityEndpoint[] storage endpoints = agentCapabilityEndpoints[agentId];
        for (uint i = 0; i < endpoints.length; i++) {
            if (keccak256(bytes(endpoints[i].capability)) == keccak256(bytes(capability))) {
                return (endpoints[i].endpoint, endpoints[i].accessInstructions);
            }
        }
        return ("", "");
    }

    /**
     * @dev Publish an intent to the blockchain
     */
    function publishIntent(
        string memory agentId,
        string memory intentType,
        string memory description,
        string memory data,
        string[] memory requiredCapabilities,
        uint256 expiry
    ) public payable onlyAgentOwner(agentId) returns (uint256) {
        if (!agents[agentId].active) revert AgentNotActive(agentId);
        if (bytes(intentType).length == 0) revert("Intent type cannot be empty");

        uint256 intentId = _intentIdCounter.current();
        _intentIdCounter.increment();

        intents[intentId] = Intent(
            intentId,
            agentId,
            intentType,
            description,
            data,
            requiredCapabilities,
            msg.value,
            expiry,
            block.timestamp,
            false,
            payable(msg.sender)
        );

        agentIntents[agentId].push(intentId);
        intentTypeIndex[intentType].push(intentId);
        for (uint i = 0; i < requiredCapabilities.length; i++) {
            capabilityIntentIndex[requiredCapabilities[i]].push(intentId);
        }

        emit IntentPublished(intentId, agentId, intentType);
        return intentId;
    }

    /**
     * @dev Perform an action in response to an intent
     */
    function performAction(
        uint256 intentId,
        string memory agentId,
        string memory actionType,
        string memory data,
        string memory evidence,
        bytes32 evidenceHash,
        bytes32 accessTokenId,
        bool proxyMode,
        bool requiresCallback
    ) public onlyAgentOwner(agentId) returns (uint256) {
        if (!agents[agentId].active) revert AgentNotActive(agentId);
        if (intentId >= _intentIdCounter.current()) revert IntentDoesNotExist(intentId);
        if (intents[intentId].fulfilled) revert IntentAlreadyFulfilled(intentId);
        if (intents[intentId].expiry > 0 && block.timestamp > intents[intentId].expiry) revert IntentExpired(intentId);

        // Enforce proxy mode constraints
        if (proxyMode && accessTokenId != bytes32(0)) revert InvalidProxyAction(accessTokenId);
        if (proxyMode && evidenceHash == bytes32(0)) revert("Evidence hash required for proxy mode");

        uint256 actionId = _actionIdCounter.current();
        _actionIdCounter.increment();

        actions[actionId] = Action(
            actionId,
            intentId,
            agentId,
            actionType,
            data,
            evidence,
            evidenceHash,
            accessTokenId,
            proxyMode,
            requiresCallback,
            block.timestamp,
            false,
            msg.sender
        );

        agentActions[agentId].push(actionId);

        if (proxyMode) {
            emit ProxyActionPerformed(actionId, intentId, agentId, evidenceHash);
        } else {
            emit ActionPerformed(actionId, intentId, agentId);
        }
        return actionId;
    }

    /**
     * @dev Accept an action as fulfillment of an intent
     */
    function acceptAction(uint256 actionId, uint256 intentId) public returns (bool) {
        if (actionId >= _actionIdCounter.current()) revert ActionDoesNotExist(actionId);
        if (intentId >= _intentIdCounter.current()) revert IntentDoesNotExist(intentId);

        Action storage action = actions[actionId];
        Intent storage intent = intents[intentId];

        if (action.intentId != intentId) revert("Action does not match intent");
        if (action.accepted) revert("Action already accepted");
        if (intent.fulfilled) revert IntentAlreadyFulfilled(intentId);
        if (intent.publisher != msg.sender) revert("Not authorized to accept this action");

        action.accepted = true;
        intent.fulfilled = true;

        if (intent.reward > 0) {
            (bool sent, ) = action.actor.call{value: intent.reward}("");
            if (!sent) {
                revert RewardTransferFailed(action.actor, intent.reward);
            }
        }

        emit ActionAccepted(actionId, intentId);
        return true;
    }

    /**
     * @dev Create an access token for API access delegation
     */
    function createAccessToken(
        string memory issuerAgentId,
        string memory targetAgentId,
        string memory capability,
        string memory accessData,
        uint256 expiryTime,
        uint256 usageLimit
    ) public onlyAgentOwner(issuerAgentId) returns (bytes32) {
        if (!agents[issuerAgentId].active) revert AgentNotActive(issuerAgentId);
        if (bytes(targetAgentId).length == 0) revert("Target agent ID cannot be empty");
        if (bytes(agents[targetAgentId].agentId).length == 0) revert AgentDoesNotExist(targetAgentId);
        if (bytes(capability).length == 0) revert("Capability cannot be empty");

        bool hasCapability = false;
        for (uint i = 0; i < agents[issuerAgentId].capabilities.length; i++) {
            if (keccak256(bytes(agents[issuerAgentId].capabilities[i])) == keccak256(bytes(capability))) {
                hasCapability = true;
                break;
            }
        }
        if (!hasCapability) revert("Issuer agent does not have this capability");

        bytes32 tokenId = keccak256(abi.encodePacked(
            issuerAgentId,
            targetAgentId,
            capability,
            block.timestamp,
            msg.sender
        ));

        accessTokens[tokenId] = AccessToken(
            tokenId,
            issuerAgentId,
            targetAgentId,
            capability,
            accessData,
            block.timestamp + expiryTime,
            usageLimit,
            0,
            false,
            block.timestamp
        );

        agentIssuedTokens[issuerAgentId].push(tokenId);
        agentReceivedTokens[targetAgentId].push(tokenId);

        emit AccessTokenCreated(tokenId, issuerAgentId, targetAgentId, capability);
        return tokenId;
    }

    /**
     * @dev Revoke an access token
     */
    function revokeAccessToken(bytes32 tokenId) public returns (bool) {
        if (tokenId == bytes32(0)) revert TokenDoesNotExist(tokenId);
        if (accessTokens[tokenId].id != tokenId) revert TokenDoesNotExist(tokenId);

        AccessToken storage token = accessTokens[tokenId];
        if (agents[token.issuerAgentId].owner != msg.sender) revert NotAgentOwner(token.issuerAgentId, msg.sender);

        token.revoked = true;
        emit AccessTokenRevoked(tokenId);
        return true;
    }

    /**
     * @dev Use an access token
     */
    function useAccessToken(bytes32 tokenId) public returns (bool) {
        if (tokenId == bytes32(0)) revert TokenDoesNotExist(tokenId);
        if (accessTokens[tokenId].id != tokenId) revert TokenDoesNotExist(tokenId);

        AccessToken storage token = accessTokens[tokenId];
        if (token.revoked) revert TokenRevoked(tokenId);
        if (block.timestamp > token.expiresAt) revert TokenExpired(tokenId);
        if (token.usageCount >= token.usageLimit && token.usageLimit > 0) revert TokenUsageLimitReached(tokenId);
        if (agents[token.targetAgentId].owner != msg.sender) revert NotTargetAgent(tokenId, msg.sender);
        if (!agents[token.targetAgentId].active) revert AgentNotActive(token.targetAgentId);

        token.usageCount++;
        emit AccessTokenUsed(tokenId, token.usageCount);
        return true;
    }

    /**
     * @dev Get access token details
     */
    function getAccessToken(bytes32 tokenId) public view returns (
        string memory issuerAgentId,
        string memory targetAgentId,
        string memory capability,
        string memory accessData,
        uint256 expiresAt,
        uint256 usageLimit,
        uint256 usageCount,
        bool revoked
    ) {
        if (tokenId == bytes32(0)) revert TokenDoesNotExist(tokenId);
        if (accessTokens[tokenId].id != tokenId) revert TokenDoesNotExist(tokenId);

        AccessToken storage token = accessTokens[tokenId];
        return (
            token.issuerAgentId,
            token.targetAgentId,
            token.capability,
            token.accessData,
            token.expiresAt,
            token.usageLimit,
            token.usageCount,
            token.revoked
        );
    }

    /**
     * @dev Verify if an access token is valid
     */
    function verifyAccessToken(bytes32 tokenId) public view returns (bool) {
        if (tokenId == bytes32(0) || accessTokens[tokenId].id != tokenId) return false;

        AccessToken storage token = accessTokens[tokenId];
        if (token.revoked) return false;
        if (block.timestamp > token.expiresAt) return false;
        if (token.usageCount >= token.usageLimit && token.usageLimit > 0) return false;

        return true;
    }

    /**
     * @dev Subscribe an agent to a specific intent type
     */
    function subscribe(string memory agentId, string memory intentType) public onlyAgentOwner(agentId) returns (bool) {
        if (bytes(intentType).length == 0) revert("Intent type cannot be empty");

        bytes32 subKey = keccak256(abi.encodePacked(agentId, intentType));
        if (!hasSubscription[subKey]) {
            agentSubscriptions[agentId].push(intentType);
            hasSubscription[subKey] = true;
            emit SubscriptionAdded(agentId, intentType);
        }
        return true;
    }

    /**
     * @dev Unsubscribe an agent from a specific intent type
     */
    function unsubscribe(string memory agentId, string memory intentType) public onlyAgentOwner(agentId) returns (bool) {
        if (bytes(intentType).length == 0) revert("Intent type cannot be empty");

        bytes32 subKey = keccak256(abi.encodePacked(agentId, intentType));
        if (hasSubscription[subKey]) {
            string[] storage subscriptions = agentSubscriptions[agentId];
            for (uint i = 0; i < subscriptions.length; i++) {
                if (keccak256(bytes(subscriptions[i])) == keccak256(bytes(intentType))) {
                    if (i < subscriptions.length - 1) {
                        subscriptions[i] = subscriptions[subscriptions.length - 1];
                    }
                    subscriptions.pop();
                    break;
                }
            }
            hasSubscription[subKey] = false;
            emit SubscriptionRemoved(agentId, intentType);
        }
        return true;
    }

    /**
     * @dev Get all active intents for a specific intent type
     */
    function getIntentsByType(string memory intentType, bool includeExpired, uint256 limit) 
        public view returns (uint256[] memory)
    {
        uint256[] storage allIntents = intentTypeIndex[intentType];
        uint256 validCount = 0;
        for (uint i = 0; i < allIntents.length; i++) {
            Intent storage intent = intents[allIntents[i]];
            if (!intent.fulfilled && (includeExpired || intent.expiry == 0 || block.timestamp <= intent.expiry)) {
                validCount++;
            }
        }

        uint256 resultSize = limit > 0 && limit < validCount ? limit : validCount;
        uint256[] memory result = new uint256[](resultSize);

        uint256 resultIndex = 0;
        for (uint i = 0; i < allIntents.length && resultIndex < resultSize; i++) {
            Intent storage intent = intents[allIntents[i]];
            if (!intent.fulfilled && (includeExpired || intent.expiry == 0 || block.timestamp <= intent.expiry)) {
                result[resultIndex] = allIntents[i];
                resultIndex++;
            }
        }
        return result;
    }

    /**
     * @dev Get all active intents requiring a specific capability
     */
    function getIntentsByCapability(string memory capability, uint256 limit) 
        public view returns (uint256[] memory)
    {
        uint256[] storage allIntents = capabilityIntentIndex[capability];
        uint256 validCount = 0;
        for (uint i = 0; i < allIntents.length; i++) {
            Intent storage intent = intents[allIntents[i]];
            if (!intent.fulfilled && (intent.expiry == 0 || block.timestamp <= intent.expiry)) {
                validCount++;
            }
        }

        uint256 resultSize = limit > 0 && limit < validCount ? limit : validCount;
        uint256[] memory result = new uint256[](resultSize);

        uint256 resultIndex = 0;
        for (uint i = 0; i < allIntents.length && resultIndex < resultSize; i++) {
            Intent storage intent = intents[allIntents[i]];
            if (!intent.fulfilled && (intent.expiry == 0 || block.timestamp <= intent.expiry)) {
                result[resultIndex] = allIntents[i];
                resultIndex++;
            }
        }
        return result;
    }

    /**
     * @dev Get all agents with a specific capability
     */
    function getAgentsByCapability(string memory capability, bool activeOnly) 
        public view returns (string[] memory)
    {
        uint256 count = 0;
        for (uint i = 0; i < registeredAgentIds.length; i++) {
            if (activeOnly && !activeAgents[registeredAgentIds[i]]) continue;

            bool hasCapability = false;
            for (uint j = 0; j < agents[registeredAgentIds[i]].capabilities.length; j++) {
                if (keccak256(bytes(agents[registeredAgentIds[i]].capabilities[j])) == keccak256(bytes(capability))) {
                    hasCapability = true;
                    break;
                }
            }
            if (hasCapability) count++;
        }

        string[] memory result = new string[](count);
        uint256 resultIndex = 0;
        for (uint i = 0; i < registeredAgentIds.length; i++) {
            if (activeOnly && !activeAgents[registeredAgentIds[i]]) continue;

            bool hasCapability = false;
            for (uint j = 0; j < agents[registeredAgentIds[i]].capabilities.length; j++) {
                if (keccak256(bytes(agents[registeredAgentIds[i]].capabilities[j])) == keccak256(bytes(capability))) {
                    hasCapability = true;
                    break;
                }
            }
            if (hasCapability) {
                result[resultIndex] = registeredAgentIds[i];
                resultIndex++;
            }
        }
        return result;
    }

    /**
     * @dev Get all subscriptions for an agent
     */
    function getAgentSubscriptions(string memory agentId) public view returns (string[] memory) {
        return agentSubscriptions[agentId];
    }

    /**
     * @dev Get all registered agents
     */
    function getAllAgents(bool activeOnly) public view returns (string[] memory) {
        if (!activeOnly) {
            return registeredAgentIds;
        }

        uint256 activeCount = 0;
        for (uint i = 0; i < registeredAgentIds.length; i++) {
            if (activeAgents[registeredAgentIds[i]]) {
                activeCount++;
            }
        }

        string[] memory result = new string[](activeCount);
        uint256 resultIndex = 0;
        for (uint i = 0; i < registeredAgentIds.length; i++) {
            if (activeAgents[registeredAgentIds[i]]) {
                result[resultIndex] = registeredAgentIds[i];
                resultIndex++;
            }
        }
        return result;
    }

    /**
     * @dev Get all access tokens issued by an agent
     */
    function getAgentIssuedTokens(string memory agentId) public view returns (bytes32[] memory) {
        return agentIssuedTokens[agentId];
    }

    /**
     * @dev Get all access tokens received by an agent
     */
    function getAgentReceivedTokens(string memory agentId) public view returns (bytes32[] memory) {
        return agentReceivedTokens[agentId];
    }

    /**
     * @dev Get all capabilities of an agent
     */
    function getAgentCapabilities(string memory agentId) public view returns (string[] memory) {
        if (bytes(agentId).length == 0) revert("Agent ID cannot be empty");
        if (bytes(agents[agentId].agentId).length == 0) revert AgentDoesNotExist(agentId);
        return agents[agentId].capabilities;
    }

    /**
     * @dev Get all actions performed for an intent
     */
    function getActionsForIntent(uint256 intentId) public view returns (uint256[] memory) {
        if (intentId >= _intentIdCounter.current()) revert IntentDoesNotExist(intentId);

        uint256 actionCount = 0;
        for (uint i = 0; i < _actionIdCounter.current(); i++) {
            if (actions[i].intentId == intentId) {
                actionCount++;
            }
        }

        uint256[] memory result = new uint256[](actionCount);
        uint256 resultIndex = 0;
        for (uint i = 0; i < _actionIdCounter.current(); i++) {
            if (actions[i].intentId == intentId) {
                result[resultIndex] = i;
                resultIndex++;
            }
        }
        return result;
    }

    /**
     * @dev Get intent details
     */
    function getIntentDetails(uint256 intentId) public view returns (
        string memory agentId,
        string memory intentType,
        string memory description,
        string memory data,
        uint256 timestamp,
        uint256 expiry,
        bool fulfilled
    ) {
        if (intentId >= _intentIdCounter.current()) revert IntentDoesNotExist(intentId);
        Intent storage intent = intents[intentId];
        return (
            intent.agentId,
            intent.intentType,
            intent.description,
            intent.data,
            intent.timestamp,
            intent.expiry,
            intent.fulfilled
        );
    }

    /**
     * @dev Get action details
     */
    function getActionDetails(uint256 actionId) public view returns (
        uint256 intentId,
        string memory agentId,
        string memory actionType,
        string memory data,
        string memory evidence,
        bytes32 evidenceHash,
        bytes32 accessTokenId,
        bool proxyMode,
        bool requiresCallback,
        uint256 timestamp,
        bool accepted
    ) {
        if (actionId >= _actionIdCounter.current()) revert ActionDoesNotExist(actionId);
        Action storage action = actions[actionId];
        return (
            action.intentId,
            action.agentId,
            action.actionType,
            action.data,
            action.evidence,
            action.evidenceHash,
            action.accessTokenId,
            action.proxyMode,
            action.requiresCallback,
            action.timestamp,
            action.accepted
        );
    }

    /**
     * @dev Get required capabilities for an intent
     */
    function getIntentRequiredCapabilities(uint256 intentId) public view returns (string[] memory) {
        if (intentId >= _intentIdCounter.current()) revert IntentDoesNotExist(intentId);
        return intents[intentId].requiredCapabilities;
    }

    /**
     * @dev Get total count of active intents
     */
    function getTotalActiveIntents() public view returns (uint256) {
        uint256 total = 0;
        for (uint i = 0; i < _intentIdCounter.current(); i++) {
            if (!intents[i].fulfilled && (intents[i].expiry == 0 || block.timestamp <= intents[i].expiry)) {
                total++;
            }
        }
        return total;
    }

    /**
     * @dev Get total count of registered agents
     */
    function getTotalAgents() public view returns (uint256) {
        return registeredAgentIds.length;
    }

    /**
     * @dev Get total count of active agents
     */
    function getTotalActiveAgents() public view returns (uint256) {
        uint256 total = 0;
        for (uint i = 0; i < registeredAgentIds.length; i++) {
            if (activeAgents[registeredAgentIds[i]]) {
                total++;
            }
        }
        return total;
    }
}
