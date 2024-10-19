import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';

import { User } from './entities/user.entity';

import {
  CreateUserDto,
  LoginDto,
  SignUpDto,
  UpdateAuthDto,
} from './dto';

import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService
  ) { }

  async create(createUserDto: CreateUserDto): Promise<User> {
    try {
      const { password, ...userData } = createUserDto;
      // const newUser = new this.userModel(createUserDto);

      // 1.- Encriptar la contraseña
      const newUser = new this.userModel({
        password: bcrypt.hashSync(password, 10),
        ...userData,
      });
      
      // 2.- Guardar el usuario
      
      // 3.- Generar el JWT
      
      await newUser.save();

      const { password: _password, ...user } = newUser.toObject();
      return user;

    } catch (error) {
      if(error.code === 11000) {
        throw new BadRequestException(`${createUserDto.email} already exists`);
      }

      throw new InternalServerErrorException('Something went wrong');
    }
  }

  async login( loginDto: LoginDto): Promise<LoginResponse> {
    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email });
    if(!user) {
      throw new UnauthorizedException('Invalid email or password - email');
    }

    if(!bcrypt.compareSync(password, user.password)) {
      throw new UnauthorizedException('Invalid email or password - password');
    }

    const { password: _, ...rest } = user.toJSON()

    return {
      user: rest,
      token: this.getJwtToken({ id: user.id })
    }
  }

  async register(signUpDto: SignUpDto): Promise<LoginResponse> {
    const user =await this.create(signUpDto);
    return { 
      user,
      token: this.getJwtToken({ id: user._id })
    };
  }

  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken(payload: JwtPayload): string {
    const token = this.jwtService.sign(payload);
    return token;
  }

}
