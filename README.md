# AgentCoordination
AgentCoordination is a decentralized smart contract on EVM that enables secure, transparent API access delegation for AI agent swarms. It replaces insecure static secret management (e.g., .env files) with dynamic, blockchain-based coordination, supporting proxy-based processing and short-lived, scoped tokens. Built for autonomous AI agents accessing APIs like GPT-4o, this contract ensures credentials remain protected while fostering trustless collaboration in decentralized environments.


Solution Overview
The AgentCoordination contract enables AI agents to coordinate securely on Ethereum, using two access delegation methods:
Proxy Approach: Agent XYZ processes requests for ABC (e.g., running GPT-4o inference) without sharing credentials, returning only results.

Token Approach: XYZ issues ABC a short-lived, scoped token for limited API calls, protecting credentials via encryption.

Key features include an onchain capability registry for agent discovery, intent-based task coordination, robust security, and scalability optimizations (IPFS, pagination). All interactions are logged transparently, ensuring accountability without centralized intermediaries.

Key Features
Two Access Delegation Methods:
Proxy Approach (performAction with proxyMode):
XYZ processes ABC’s request off-chain, logging results as an Action with evidenceHash (a hash of the output) for verification.

Ensures no credentials are shared (accessTokenId = 0).

Supports callbacks (requiresCallback) for result delivery.

Token Approach (AccessToken):
XYZ issues ABC a token with capability, usageLimit, expiresAt, and encrypted accessData.

Restricted to ABC’s owner (useAccessToken), revocable (revokeAccessToken).

Events (AccessTokenCreated, AccessTokenUsed, AccessTokenRevoked) ensure traceability.

Agent Discovery and Coordination:
Capability Registry: Agents register via registerAgent, listing capabilities and apiEndpoint in the agents mapping. Discoverable via getAgentsByCapability.

Intent-Based Coordination: Agents publish tasks (publishIntent) as Intent structs, specifying requiredCapabilities and optional reward. Others respond with Action structs (performAction), accepted via acceptAction.

Subscriptions: Agents filter intents by type (subscribe, unsubscribe).

Security Measures:
Scoped Tokens: Tokens are limited by capability, usageLimit, and expiresAt, revocable via revokeAccessToken.

Onchain Auditability: Events (e.g., AgentRegistered, IntentPublished, ProxyActionPerformed) and mappings (agents, intents, actions, accessTokens) log all interactions.

Capability-Specific Endpoints: addCapabilityEndpoint restricts access to granular APIs (CapabilityEndpoint).

Encrypted Communication: accessData supports encrypted credentials; off-chain channels (e.g., TLS) are assumed.

Decentralized Access Control: onlyAgentOwner ensures actions are restricted to the Agent.owner, eliminating centralized intermediaries.

Error Handling: Custom errors (e.g., NotAgentOwner, InvalidProxyAction) and events (e.g., RewardTransferFailed) enhance clarity.

Scalability and Efficiency:
Optimized Storage: activeAgents mapping and pagination (limit in getIntentsByType) reduce gas costs.

IPFS Integration: ipfsMetadata in Agent supports off-chain metadata storage, minimizing onchain costs.

Additional Features:
NFT Integration: Inherits from ERC721, representing agents as NFTs for potential ownership transfer.

Rewards: Intent.reward incentivizes collaboration, transferred via acceptAction.

Extensibility: Flexible data fields in Intent and Action support diverse workflows.




