using AngularAuthAPI.Context;
using AngularAuthAPI.Helpers;
using AngularAuthAPI.Models;
using AngularAuthAPI.Models.DTO_s;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;

namespace AngularAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly IMapper _mapper;
        public UserController(AppDbContext context, IConfiguration configuration, IMapper mapper)
        {
            _context = context;
            _configuration = configuration;
            _mapper = mapper;
        }

        [HttpPost("authenticate")]
        public async Task<ActionResult<UserDto>> Authenticate([FromBody] LoginDto loginObj)
        {
            if (loginObj == null)
                return BadRequest(new { Message = "Form is empty" });

            var user = await _context.Users.FirstOrDefaultAsync(x => x.Username == loginObj.Username);

            if (user == null)
                return NotFound(new { message = "User Not Found!" });

            if (!PasswordHasher.VerifyPassword(loginObj.Password, user.Password))
                return BadRequest(new { message = "Log in failed" });

            user.Token = CreateToken(user);
            UserDto userDto = _mapper.Map<UserDto>(user);

            return Ok(user);
        }

        [HttpPost("add")]
        public async Task<IActionResult> AddUser([FromBody] User userObj)
        {
            try
            {
                // check email
                if (await checkEmailExistAsync(userObj.Email))
                    return BadRequest(new { Message="Email Already Exist" });

                //check username
                if (await checkUsernameExistAsync(userObj.Username))
                    return BadRequest(new { Message = "Username Already Exist" });

                var passMessage = CheckPasswordStrength(userObj.Password);
                if(!string.IsNullOrEmpty(passMessage))
                    return BadRequest(new { Message = passMessage.ToString() });

                userObj.Password = PasswordHasher.HashPassword(userObj.Password);
                userObj.Role = "User";
                userObj.Token = "";
                await _context.AddAsync(userObj);
                await _context.SaveChangesAsync();
                return Ok(new
                {
                    Status = 200,
                    Message = "User Added!"
                });
            }
            catch (Exception)
            {

                throw;
            }
        }

        //[Authorize(Roles = "User")]
        [HttpGet]
        public async Task<ActionResult<List<User>>> GetAllUsers()
        {
            //return await _context.Users
            //    .Select(x => new User()
            //    {
            //        Id = x.Id,
            //        FirstName = x.FirstName,
            //        LastName = x.LastName,
            //        Username = x.Username,
            //        Password = null,
            //        Role = x.Role,
            //        Email = x.Email
            //    })
            //    .ToListAsync();
            var users = _mapper.Map<List<User>, List<UserDto>>(await _context.Users.ToListAsync());
            return Ok(await _context.Users.ToListAsync());
        }

        private string CreateToken(User user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration.GetSection("AppSettings:SecretKey").Value);
            var identity = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Role, user.Role)
                });
            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddDays(2),
                SigningCredentials = credentials
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            return jwtTokenHandler.WriteToken(token);
        }

        private Task<bool> checkEmailExistAsync(string email)
            => _context.Users.AnyAsync(x => x.Email == email);

        private Task<bool> checkUsernameExistAsync(string username)
            => _context.Users.AnyAsync(x => x.Email == username);

        private string CheckPasswordStrength(string pass)
        {
            StringBuilder sb = new StringBuilder();
            if (pass.Length < 9)
                sb.Append("Minimum password length should be 8"+Environment.NewLine);
            if (!(Regex.IsMatch(pass, "[a-z]") && Regex.IsMatch(pass, "[A-Z]") && Regex.IsMatch(pass, "[0-9]")))
                sb.Append("Password should be AlphaNumeric" + Environment.NewLine);
            if (!Regex.IsMatch(pass, "[<,>,@,!,#,$,%,^,&,*,(,),_,+,\\[,\\],{,},?,:,;,|,',\\,.,/,~,`,-,=]"))
                sb.Append("Password should contain special charcter" + Environment.NewLine);
            return sb.ToString();
        }
    }
}
