import { Controller, Get } from '@nestjs/common';

@Controller({ path: 'admin' })
export class AdminController {
  @Get('stats')
  stats() {
    return { users: 0 };
  }
}
