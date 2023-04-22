export class Logger {
  private _logLevel: LogLevels;

  constructor(logLevel: string | LogLevels) {
    this._logLevel = (typeof logLevel === 'string' ? LogLevels[logLevel] : logLevel) || LogLevels.INFO;
  }

  log(level: LogLevels, message: string) {
    if (this._logLevel <= level) {
      if (level < LogLevels.ERROR) {
        console.log(message);
      } else {
        console.error(message);
      }
    }
  }

  debug(message: string) { this.log(LogLevels.DEBUG, message); }
  info(message: string) { this.log(LogLevels.INFO, message); }
  warn(message: string) { this.log(LogLevels.WARN, message); }
  error(message: string) { this.log(LogLevels.ERROR, message); }
  fatal(message: string) { this.log(LogLevels.FATAL, message); }
}

export enum LogLevels {
  "DEBUG" = 1,
  "INFO" = 2,
  "WARN" = 3,
  "ERROR" = 4,
  "FATAL" = 5
};

export default Logger;

