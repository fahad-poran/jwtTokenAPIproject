using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using dotnet_rpg.Dtos.User;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace dotnet_rpg.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthRepository _authRepo;

        public AuthController(IAuthRepository authRepo)
        {
            _authRepo = authRepo;
        }

        [HttpPost("Register")]
        public async Task<ActionResult<ServiceResponse<int>>> Register(UserRegisterDto request)
        {
            var response = await _authRepo.Register(
                new User { Username = request.Username }, request.Password
            );
            if (!response.Success)
            {
                return BadRequest(response);
            }
            // for 201 we need to return the path to a newly created resource.
            // response data should be new User's ID
            return CreatedAtAction(
                nameof(GetCreatedUser), new { id = response.Data }, response
            );
        }
        [HttpGet("{id}", Name = "GetCreatedUser")]
        public async Task<ActionResult<User>> GetCreatedUser(int id)
        {
            var user = await _authRepo.GetUserAsync(id);
            if (user == null)
            {
                return NotFound(); // return standard 404 not found
            }
            return Ok(user); // returns 200
        }

        [HttpPost("Login")]
        public async Task<ActionResult<ServiceResponse<int>>> Login(UserLoginDto request)
        {
            var response = await _authRepo.Login(request.Username, request.Password);
            if(!response.Success)
            {
                return BadRequest(response);
            }
            return Ok(response);
        }
    }
}