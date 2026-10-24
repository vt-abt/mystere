export const STATE = Object.freeze({
  HEALTHY: 'HEALTHY',
  DELAYED: 'DELAYED',
  SUSPECTED: 'SUSPECTED',
  FROZEN: 'FROZEN',
})

export const EVENT = Object.freeze({
  TIMEOUT: 'TIMEOUT_NO_MESSAGE',
  AUTH_FAILURE: 'AUTH_FAILURE',
  OUT_OF_ORDER: 'OUT_OF_ORDER',
  HEALTHY_MESSAGE: 'HEALTHY_MESSAGE',
})

export class SessionStateMachine {
  constructor(onFreeze, onChange = () => {}) {
    this.state = STATE.HEALTHY
    this.onFreeze = onFreeze
    this.onChange = onChange
  }

  async handleEvent(event) {
    if (this.state === STATE.FROZEN) return
    if (event === EVENT.AUTH_FAILURE) {
      this.state = STATE.FROZEN
      this.onChange(this.state)
      await this.onFreeze?.('AUTH_FAILURE')
      return
    }
    if (event === EVENT.TIMEOUT && this.state === STATE.HEALTHY) {
      this.state = STATE.DELAYED
    } else if (event === EVENT.OUT_OF_ORDER) {
      this.state = STATE.SUSPECTED
    } else if (event === EVENT.HEALTHY_MESSAGE) {
      this.state = STATE.HEALTHY
    } else {
      return
    }
    this.onChange(this.state)
  }
}
