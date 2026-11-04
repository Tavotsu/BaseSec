import { Module } from '@nestjs/common';
import { UsersController } from './users/users.controller';
import { AdminController } from './admin/admin.controller';

@Module({
  controllers: [UsersController, AdminController],
})
export class AppModule {}
