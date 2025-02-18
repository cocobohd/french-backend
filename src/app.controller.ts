import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { AuthGuard } from './guards/auth.guard';

@Controller()
export class AppController {
  @Get()
  someProtectedRoute() {
    return { message: 'Accessed Resourses' };
  }
}
