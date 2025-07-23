from django.shortcuts import render, redirect, get_object_or_404
from .models import QuizCategory, Question, Answer, QuizSession, QuizResult, QuizAttempt
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.db.models import Prefetch
import random
import json

def quiz_home(request):
    categories = QuizCategory.objects.filter(is_active=True)
    # home.html-ը անփոփոխ, ուղարկում ենք կոնտեքստը
    return render(request, 'quiz/home.html', {'categories': categories, 'Question': Question})

def start_quiz(request):
    if request.method == 'POST':
        category_id = request.POST.get('category')
        question_type = request.POST.get('question_type')
        if not category_id or not question_type:
            return render(request, 'quiz/home.html', {
                'categories': QuizCategory.objects.filter(is_active=True),
                'Question': Question,
                'error': 'Խնդրում ենք ընտրել կատեգորիա և հարցի տեսակ։'
            })
        category = get_object_or_404(QuizCategory, id=category_id)
        questions = Question.objects.filter(category=category, question_type=question_type, is_active=True)
        if not questions.exists():
            return render(request, 'quiz/home.html', {
                'categories': QuizCategory.objects.filter(is_active=True),
                'Question': Question,
                'error': 'Հարցեր չկան այս կատեգորիայում։'
            })
        session = QuizSession.objects.create(
            session_key=str(random.randint(1000000, 9999999)),
            category=category,
            question_type=question_type,
            current_question=0,
            score=0,
        )
        request.session['quiz_session_id'] = session.id
        return redirect('quiz:quiz_question', session.id)
    return redirect('quiz:home')

def quiz_question(request, session_id):
    session = get_object_or_404(QuizSession, id=session_id)
    if session.is_completed:
        return redirect('quiz:quiz_result', session.id)
    questions = Question.objects.filter(
        category=session.category,
        question_type=session.question_type,
        is_active=True
    ).select_related('category').prefetch_related('answers').order_by('difficulty')
    total_questions = questions.count()
    if session.current_question >= total_questions:
        session.is_completed = True
        session.save()
        return redirect('quiz:quiz_result', session.id)
    question = questions[session.current_question]
    answers = list(question.answers.all())
    random.shuffle(answers)
    progress = int((session.current_question + 1) / total_questions * 100)
    template_name = f'quiz/{session.question_type}.html'
    return render(request, template_name, {
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
    if session.is_completed:
        return JsonResponse({'error': 'Quiz already completed'}, status=400)
    questions = Question.objects.filter(
        category=session.category,
        question_type=session.question_type,
        is_active=True
    ).select_related('category').prefetch_related('answers').order_by('difficulty')
    total_questions = questions.count()
    if session.current_question >= total_questions:
        session.is_completed = True
        session.save()
        return JsonResponse({'redirect': 'result'})
    question = questions[session.current_question]
    answer_id = None
    if request.method == 'POST':
        if request.content_type and 'application/json' in request.content_type:
            try:
                data = json.loads(request.body)
                answer_id = data.get('answer_id')
            except json.JSONDecodeError:
                pass
        else:
            answer_id = request.POST.get('answer_id')
    if not answer_id:
        return JsonResponse({'error': 'No answer provided'}, status=400)
    answer = get_object_or_404(Answer, id=answer_id)
    correct = answer.is_correct
    points_earned = question.points if correct else 0
    QuizAttempt.objects.create(
        session=session,
        question=question,
        answer=answer,
        is_correct=correct
    )
    session.score += points_earned
    session.current_question += 1
    session.save()
    if session.current_question >= total_questions:
        session.is_completed = True
        session.save()
    return JsonResponse({
        'correct': correct,
        'explanation': question.explanation or "Բացատրություն չկա",
        'points_earned': points_earned,
    })

def quiz_result(request, session_id):
    session = get_object_or_404(QuizSession, id=session_id)
    attempts = QuizAttempt.objects.filter(session=session)
    correct_count = attempts.filter(is_correct=True).count()
    incorrect_count = attempts.filter(is_correct=False).count()
    questions = Question.objects.filter(
        category=session.category,
        question_type=session.question_type,
        is_active=True
    )
    total_possible_score = sum(q.points for q in questions)
    percentage = int((session.score / total_possible_score) * 100) if total_possible_score else 0
    character_result = 'ara' if percentage >= 70 else 'shamiram'
    feedback_message = (
        "Շնորհավորում ենք! Դուք Արա Գեղեցիկի կողմնակից եք: Դուք ունեք կիբեռանվտանգության բարձր գիտելիքներ և կարող եք հաջողությամբ պաշտպանվել կիբեռսպառնալիքներից։"
        if character_result == 'ara' else
        "Դուք Շամիրամի կողմնակից եք: Պահպանեք զգոնությունը և շարունակեք զարգացնել ձեր կիբեռանվտանգության հմտությունները։ Ուսումնասիրեք մեր նյութերը ավելի շատ գիտելիքների համար։"
    )
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
        'total_possible_score': total_possible_score,
        'correct_count': correct_count,
        'incorrect_count': incorrect_count,
    })

def leaderboard(request):
    results = QuizResult.objects.filter(
        is_visible=True
    ).select_related(
        'session', 'session__category'
    ).order_by('-percentage', '-final_score', '-session__started_at')[:10]
    return render(request, 'quiz/leaderboard.html', {'results': results})