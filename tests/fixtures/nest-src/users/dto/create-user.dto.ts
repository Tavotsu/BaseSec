export class CreateUserDto {
  email: string;
  age: number;

  validate(): boolean {
    return this.email.length > 0;
  }
}
