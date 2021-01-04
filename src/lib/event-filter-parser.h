/* A Bison parser, made by GNU Bison 3.0.4.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

#ifndef YY_EVENT_FILTER_PARSER_EVENT_FILTER_PARSER_H_INCLUDED
# define YY_EVENT_FILTER_PARSER_EVENT_FILTER_PARSER_H_INCLUDED
/* Debug traces.  */
#ifndef EVENT_FILTER_PARSER_DEBUG
# if defined YYDEBUG
#if YYDEBUG
#   define EVENT_FILTER_PARSER_DEBUG 1
#  else
#   define EVENT_FILTER_PARSER_DEBUG 0
#  endif
# else /* ! defined YYDEBUG */
#  define EVENT_FILTER_PARSER_DEBUG 0
# endif /* ! defined YYDEBUG */
#endif  /* ! defined EVENT_FILTER_PARSER_DEBUG */
#if EVENT_FILTER_PARSER_DEBUG
extern int event_filter_parser_debug;
#endif

/* Token type.  */
#ifndef EVENT_FILTER_PARSER_TOKENTYPE
# define EVENT_FILTER_PARSER_TOKENTYPE
  enum event_filter_parser_tokentype
  {
    TOKEN = 258,
    STRING = 259,
    AND = 260,
    OR = 261,
    NOT = 262
  };
#endif

/* Value type.  */
#if ! defined EVENT_FILTER_PARSER_STYPE && ! defined EVENT_FILTER_PARSER_STYPE_IS_DECLARED

union EVENT_FILTER_PARSER_STYPE
{
#line 132 "event-filter-parser.y" /* yacc.c:1909  */

	const char *str;
	enum event_filter_node_op op;
	struct event_filter_node *node;

#line 76 "event-filter-parser.h" /* yacc.c:1909  */
};

typedef union EVENT_FILTER_PARSER_STYPE EVENT_FILTER_PARSER_STYPE;
# define EVENT_FILTER_PARSER_STYPE_IS_TRIVIAL 1
# define EVENT_FILTER_PARSER_STYPE_IS_DECLARED 1
#endif



int event_filter_parser_parse (struct event_filter_parser_state *state);

#endif /* !YY_EVENT_FILTER_PARSER_EVENT_FILTER_PARSER_H_INCLUDED  */
