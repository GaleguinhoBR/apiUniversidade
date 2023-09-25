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
    public class DisciplinaController : Controller
    {
        private readonly ILogger<DisciplinaController> _logger;

        public DisciplinaController(ILogger<DisciplinaController> logger)
        {
            _logger = logger;
        }
        [HttpGet(Name = "disciplinas")]
        public List<Disciplina> GetDisciplina(){
            List<Disciplina> Disciplinas = new List<Disciplina>();

            Disciplina d1 = new Disciplina();
            d1.Nome = "programação para internet";
            d1.CargaHoraria = 60;
            d1.Semestre = 8;

            Disciplina d2 = new Disciplina();
            d2.Nome = "projeto de Software";
            d2.CargaHoraria = 60;
            d2.Semestre = 8;

            Disciplina d3 = new Disciplina();
            d3.Nome = "Autoria Web";
            d3.CargaHoraria = 60;
            d3.Semestre = 8;

            Disciplinas.Add(d1);
            Disciplinas.Add(d2);
            Disciplinas.Add(d3);

            return Disciplinas;
        }
    }
}