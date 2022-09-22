using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Authorization.Models
{
    public class UserModel
    {
        public string Username { get; set; }


        public string Password { get; set; }


        public bool Role { get; set; }
    }
}
