import { StrategyName } from '../config/constants.js';

/**
 * Typed message sending to the Python host via Frida send().
 */

export interface DexFoundMessage {
    type: 'dex_found';
    strategy: StrategyName;
    size: number;
    address?: string;
    loader?: string;
    path?: string;
    location?: string;
}

export interface ClassLoadedMessage {
    type: 'class_loaded';
    name: string;
    loader: string;
    strategy: StrategyName;
}

export interface ClassLoaderFoundMessage {
    type: 'classloader_found';
    id: string;
    loaderType: string;
    parent: string;
}

export interface ScanProgressMessage {
    type: 'scan_progress';
    scanned: number;
    total: number;
    found: number;
}

export interface StrategyStatusMessage {
    type: 'strategy_status';
    strategy: StrategyName;
    status: 'active' | 'skipped' | 'error' | 'complete';
    message: string;
}

export interface ErrorMessage {
    type: 'error';
    strategy: StrategyName | 'core';
    message: string;
}

export interface InfoMessage {
    type: 'info';
    message: string;
}

export type AgentMessage =
    | DexFoundMessage
    | ClassLoadedMessage
    | ClassLoaderFoundMessage
    | ScanProgressMessage
    | StrategyStatusMessage
    | ErrorMessage
    | InfoMessage;

export function sendDexFound(
    strategy: StrategyName,
    dexBytes: ArrayBuffer,
    extra?: { address?: string; loader?: string; path?: string; location?: string }
): void {
    const msg: DexFoundMessage = {
        type: 'dex_found',
        strategy,
        size: dexBytes.byteLength,
        ...extra,
    };
    send(msg, dexBytes);
}

export function sendClassLoaded(name: string, loader: string, strategy: StrategyName): void {
    const msg: ClassLoadedMessage = { type: 'class_loaded', name, loader, strategy };
    send(msg);
}

export function sendClassLoaderFound(id: string, loaderType: string, parent: string): void {
    const msg: ClassLoaderFoundMessage = { type: 'classloader_found', id, loaderType, parent };
    send(msg);
}

export function sendScanProgress(scanned: number, total: number, found: number): void {
    const msg: ScanProgressMessage = { type: 'scan_progress', scanned, total, found };
    send(msg);
}

export function sendStrategyStatus(
    strategy: StrategyName,
    status: StrategyStatusMessage['status'],
    message: string
): void {
    const msg: StrategyStatusMessage = { type: 'strategy_status', strategy, status, message };
    send(msg);
}

export function sendError(strategy: StrategyName | 'core', message: string): void {
    const msg: ErrorMessage = { type: 'error', strategy, message };
    send(msg);
}

export function sendInfo(message: string): void {
    const msg: InfoMessage = { type: 'info', message };
    send(msg);
}
