import { Address, xdr } from "@stellar/stellar-sdk";
import { sc } from "./scval.js";

/**
 * Typed argument builders for the `paymaster` contract.
 *
 * These mirror the generated `@lumen/contract-bindings` output for
 * `contracts/paymaster` and replace hand-written ScVal construction at call
 * sites. Regenerate the upstream bindings in CI; this module is the thin,
 * hand-checked consumer used by `packages/core`.
 */
export const paymaster = {
  /** `initialize(owner: Address, epoch_length: u32)` */
  initialize(owner: string | Address, epochLength: number): xdr.ScVal[] {
    return [sc.address(owner), sc.u32(epochLength)];
  },

  /** `owner()` */
  owner(): xdr.ScVal[] {
    return [];
  },

  /** `epoch_length()` */
  epochLength(): xdr.ScVal[] {
    return [];
  },

  /** `current_epoch()` */
  currentEpoch(): xdr.ScVal[] {
    return [];
  },

  /** `set_spend_limit(user: Address, token: Address, limit: i128)` */
  setSpendLimit(
    user: string | Address,
    token: string | Address,
    limit: bigint | number | string,
  ): xdr.ScVal[] {
    return [sc.address(user), sc.address(token), sc.i128(limit)];
  },

  /** `spend_limit(user: Address, token: Address) -> i128` */
  spendLimit(user: string | Address, token: string | Address): xdr.ScVal[] {
    return [sc.address(user), sc.address(token)];
  },

  /** `spent_this_epoch(user: Address, token: Address) -> i128` */
  spentThisEpoch(user: string | Address, token: string | Address): xdr.ScVal[] {
    return [sc.address(user), sc.address(token)];
  },

  /** `deposit_balance(sponsor: Address, token: Address) -> i128` */
  depositBalance(sponsor: string | Address, token: string | Address): xdr.ScVal[] {
    return [sc.address(sponsor), sc.address(token)];
  },

  /** `deposit(sponsor: Address, token: Address, amount: i128) -> i128` */
  deposit(
    sponsor: string | Address,
    token: string | Address,
    amount: bigint | number | string,
  ): xdr.ScVal[] {
    return [sc.address(sponsor), sc.address(token), sc.i128(amount)];
  },

  /** `sponsor_invocation(sponsor, user, contract, function_name, token, max_fee)` */
  sponsorInvocation(args: {
    sponsor: string | Address;
    user: string | Address;
    contract: string | Address;
    functionName: string;
    token: string | Address;
    maxFee: bigint | number | string;
  }): xdr.ScVal[] {
    return [
      sc.address(args.sponsor),
      sc.address(args.user),
      sc.address(args.contract),
      sc.symbol(args.functionName),
      sc.address(args.token),
      sc.i128(args.maxFee),
    ];
  },
};

/** Decoded `SessionKey` record returned by the `session-keys` contract. */
export interface SessionKeyRecord {
  validUntil: bigint;
  allowedContracts: string[];
  allowedMethods: string[];
  maxCumulativeAmount: bigint;
  cumulativeSpent: bigint;
}

/**
 * Typed argument builders for the `session-keys` contract, mirroring the
 * generated `@lumen/contract-bindings` output for `contracts/session-keys`.
 */
export const sessionKeys = {
  /** `register_session_key(owner, session_key, valid_until, allowed_contracts, allowed_methods, max_cumulative_amount)` */
  registerSessionKey(args: {
    owner: string | Address;
    sessionKey: string | Address;
    validUntil: bigint | number | string;
    allowedContracts: Array<string | Address>;
    allowedMethods: string[];
    maxCumulativeAmount: bigint | number | string;
  }): xdr.ScVal[] {
    return [
      sc.address(args.owner),
      sc.address(args.sessionKey),
      sc.u64(args.validUntil),
      sc.vec(args.allowedContracts.map((c) => sc.address(c))),
      sc.vec(args.allowedMethods.map((m) => sc.symbol(m))),
      sc.i128(args.maxCumulativeAmount),
    ];
  },

  /** `revoke_session_key(owner: Address, session_key: Address)` */
  revokeSessionKey(owner: string | Address, sessionKey: string | Address): xdr.ScVal[] {
    return [sc.address(owner), sc.address(sessionKey)];
  },

  /** `validate_session_call(session_key, target, method, amount) -> bool` */
  validateSessionCall(args: {
    sessionKey: string | Address;
    target: string | Address;
    method: string;
    amount: bigint | number | string;
  }): xdr.ScVal[] {
    return [
      sc.address(args.sessionKey),
      sc.address(args.target),
      sc.symbol(args.method),
      sc.i128(args.amount),
    ];
  },
};
