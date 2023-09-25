using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using apiUniversidade.Model;
using Microsoft.AspNetCore.Mvc;

namespace apiUniversidade.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AlunoController : ControllerBase
    {
        private readonly ILogger<AlunoController> _logger;

        public AlunoController(ILogger<AlunoController> logger)
        {
            _logger = logger;
        }
        [HttpGet(Name = "alunos")]
        public List<Aluno> getAluno(){
            List<Aluno> alunos = new List<Aluno>();

            Aluno a1 = new Aluno();
            a1.Nome = "Isaac";
            a1.Id = 2020;
            a1.DataNascimento = "31-05-2005";
            a1.CPF = "xxx.xxx.xxx-xx";

            alunos.Add(a1);
            
            return alunos;
        }
    }
}