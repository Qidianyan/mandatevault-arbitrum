import type { Abi, Address, Hex } from "viem";
import type { PrivateKeyAccount } from "viem/accounts";

export const ARBITRUM_ONE_CHAIN_ID: number;
export const STYLUS_COPROCESSOR_ADDRESS: Address;

export interface DeployedContractHandle {
  address: Address;
  abi: Abi;
  gasUsed: bigint;
}

export interface WriteContractResult {
  txHash: Hex;
  result: unknown;
  gasUsed: bigint;
  logs: unknown[];
}

export declare class ArbitrumLocalEvm {
  timestamp: bigint;
  blockNumber: bigint;
  advanceTime(seconds: number | bigint): void;
  setTimestamp(newTs: number | bigint): void;
  writeContract(params: {
    from: Address;
    to: Address;
    abi: Abi;
    functionName: string;
    args?: readonly unknown[];
    gasLimit?: bigint;
  }): Promise<WriteContractResult>;
  tryWriteContract(params: {
    from: Address;
    to: Address;
    abi: Abi;
    functionName: string;
    args?: readonly unknown[];
    gasLimit?: bigint;
  }): Promise<{ ok: boolean; result?: unknown; errorName?: string; gasUsed: bigint }>;
  readContract(params: {
    to: Address;
    abi: Abi;
    functionName: string;
    args?: readonly unknown[];
    from?: Address;
  }): Promise<unknown>;
}

export interface ProtocolFixture {
  chain: ArbitrumLocalEvm;
  accounts: {
    ownerKey: Hex;
    agentKey: Hex;
    attackerKey: Hex;
    arbitratorKey: Hex;
    owner: PrivateKeyAccount;
    agent: PrivateKeyAccount;
    attacker: PrivateKeyAccount;
    arbitrator: PrivateKeyAccount;
    trustedProvider: Address;
    secondaryProvider: Address;
    lowRepProvider: Address;
    phishingAddress: Address;
  };
  capabilities: {
    capMarketData: Hex;
    capCompute: Hex;
  };
  contracts: {
    usdc: DeployedContractHandle;
    aavePool: DeployedContractHandle;
    aToken: { address: Address; abi: Abi };
    registry: DeployedContractHandle;
    verifier: DeployedContractHandle;
    vault: DeployedContractHandle;
  };
}

export declare function deployFullProtocolFixture(opts?: {
  initialPrincipalUsdc?: bigint;
  globalMaxRolling24h?: bigint;
  liquidityIndexRay?: bigint;
  liquidityRateRay?: bigint;
  enableStylusPrecompile?: boolean;
}): Promise<ProtocolFixture>;

export declare function signStylusEd25519Mandate(
  seed32Hex: Hex,
  digest32Hex: Hex,
): {
  pubkey: Hex;
  signature: Hex;
  authorizer: Address;
  calldata: Hex;
};
