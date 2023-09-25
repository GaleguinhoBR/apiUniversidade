using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using apiUniversidade.Model;
using Microsoft.AspNetCore.Mvc;

namespace apiUniversidade.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class CursoController : Controller
    {
       private readonly ILogger<CursoController> _logger;

        public CursoController(ILogger<CursoController> logger)
        {
            _logger = logger;
        }
        [HttpGet(Name = "cursos")]
        public List<Curso> GetDisciplina(){
            List<Curso> Cursos = new List<Curso>();

            Curso c1 = new Curso();
            c1.Nome = "Informática";
            c1.Area = "D16";
            c1.duracao = 12;

            Curso c2 = new Curso();
            c2.Nome = "Alimentos";
            c2.Area = "D17";
            c2.duracao = 12;

            Curso c3 = new Curso();
            c3.Nome = "MSI :(";
            c3.Area = "D18";
            c3.duracao = 12;

            Cursos.Add(c1);
            Cursos.Add(c2);
            Cursos.Add(c3);

            return Cursos;
        } 
    }
}