from django.shortcuts import render, redirect, get_object_or_404
from .models import QuizCategory, Question, Answer, QuizSession, QuizResult
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import random

def quiz_home(request):
    categories = QuizCategory.objects.filter(is_active=True)
    return render(request, 'quiz/home.html', {'categories': categories, 'Question': Question})

def start_quiz(request):
    if request.method == 'POST':
        category_id = request.POST.get('category')
        question_type = request.POST.get('question_type')
        category = get_object_or_404(QuizCategory, id=category_id)
        questions = Question.objects.filter(category=category, question_type=question_type, is_active=True)
        if not questions.exists():
            return render(request, 'quiz/home.html', {'categories': QuizCategory.objects.filter(is_active=True), 'Question': Question, 'error': 'Հարցեր չկան։'})
        session = QuizSession.objects.create(
            session_key=str(random.randint(1000000,9999999)),
            category=category,
            question_type=question_type,
            current_question=0,
            score=0,
        )
        request.session['quiz_session_id'] = session.id
        return redirect('quiz:quiz_question', session.id)
    categories = QuizCategory.objects.filter(is_active=True)
    return render(request, 'quiz/start.html', {'categories': categories, 'Question': Question})

def quiz_question(request, session_id):
    session = get_object_or_404(QuizSession, id=session_id)
    questions = Question.objects.filter(category=session.category, question_type=session.question_type, is_active=True)
    total_questions = questions.count()
    if session.current_question >= total_questions:
        return redirect('quiz:quiz_result', session.id)
    question = questions[session.current_question]
    answers = question.answers.all()
    progress = int((session.current_question + 1) / total_questions * 100)
    return render(request, f'quiz/{session.question_type}.html', {
        'session': session,
        'question': question,
        'answers': answers,
        'question_number': session.current_question + 1,
        'total_questions': total_questions,
        'progress': progress,
    })

@csrf_exempt
def submit_answer(request, session_id):
    session = get_object_or_404(QuizSession, id=session_id)
    questions = Question.objects.filter(category=session.category, question_type=session.question_type, is_active=True)
    total_questions = questions.count()
    question = questions[session.current_question]
    data = request.POST or request.body
    if isinstance(data, bytes):
        import json; data = json.loads(data)
    answer_id = data.get('answer_id')
    answer = get_object_or_404(Answer, id=answer_id)
    correct = answer.is_correct
    points_earned = question.points if correct else 0
    session.score += points_earned
    session.current_question += 1
    session.save()
    return JsonResponse({
        'correct': correct,
        'explanation': question.explanation,
        'points_earned': points_earned,
    })

def quiz_result(request, session_id):
    session = get_object_or_404(QuizSession, id=session_id)
    questions = Question.objects.filter(category=session.category, question_type=session.question_type, is_active=True)
    total_score = questions.count() * 10
    percentage = int((session.score / total_score) * 100) if total_score else 0
    character_result = "ara" if percentage >= 70 else "shamiram"
    feedback_message = "Դու Արա Գեղեցիկի կողմնակից ես, դու կիբեռգիտակ ես։" if character_result == "ara" else "Դու Շամիրամի կողմնակից ես, պահպանի՛ր զգոնություն, սովորի՛ր ավելին։"
    result, created = QuizResult.objects.get_or_create(
        session=session,
        defaults={
            'final_score': session.score,
            'percentage': percentage,
            'character_result': character_result,
            'feedback_message': feedback_message
        }
    )
    return render(request, 'quiz/result.html', {
        'result': result,
        'session': session,
    })
    