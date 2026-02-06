declare const console: { log(...args: any[]): void };

import { StrategyName } from '../config/constants.js';

type LogLevel = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR';

let debugEnabled = false;

export function setDebug(enabled: boolean): void {
    debugEnabled = enabled;
}

function log(level: LogLevel, tag: string, message: string): void {
    if (level === 'DEBUG' && !debugEnabled) return;
    const now = new Date();
    const time = `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
    console.log(`[${time}] [${level}] [${tag}] ${message}`);
}

function pad(n: number): string {
    return n < 10 ? '0' + n : '' + n;
}

export const logger = {
    debug(tag: string, msg: string): void { log('DEBUG', tag, msg); },
    info(tag: string, msg: string): void { log('INFO', tag, msg); },
    warn(tag: string, msg: string): void { log('WARN', tag, msg); },
    error(tag: string, msg: string): void { log('ERROR', tag, msg); },

    strategy(name: StrategyName, msg: string): void { log('INFO', `STRATEGY:${name}`, msg); },
    strategyError(name: StrategyName, msg: string): void { log('ERROR', `STRATEGY:${name}`, msg); },
};
